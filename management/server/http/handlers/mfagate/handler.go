package mfagate

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/mfa"
	nbstore "github.com/netbirdio/netbird/management/server/store"
)

type pendingMFA struct {
	redirectURL string
	userID      string
	createdAt   time.Time
}

// Handler wraps a Dex OIDC handler and intercepts authorization-code redirects
// to enforce TOTP verification for users who have MFA enabled.
// This is a pure server-side solution — no client (CLI) changes required.
type Handler struct {
	dexHandler http.Handler
	dexStorage storage.Storage
	mgmtStore  nbstore.Store
	pending    map[string]*pendingMFA
	mu         sync.Mutex
}

func New(dexHandler http.Handler, dexStorage storage.Storage, mgmtStore nbstore.Store) *Handler {
	h := &Handler{
		dexHandler: dexHandler,
		dexStorage: dexStorage,
		mgmtStore:  mgmtStore,
		pending:    make(map[string]*pendingMFA),
	}
	go h.cleanupLoop()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth2/mfa-verify" && r.Method == http.MethodPost {
		h.handleMFAVerify(w, r)
		return
	}

	buf := &bufferedWriter{header: make(http.Header), statusCode: http.StatusOK}
	h.dexHandler.ServeHTTP(buf, r)

	if buf.statusCode == http.StatusFound || buf.statusCode == http.StatusSeeOther {
		location := buf.header.Get("Location")
		if code := extractCode(location); code != "" {
			if h.interceptForMFA(w, r, location, code) {
				return
			}
		}
	}

	flushBuffered(w, buf)
}

func (h *Handler) interceptForMFA(w http.ResponseWriter, r *http.Request, redirectURL, code string) bool {
	authCode, err := h.dexStorage.GetAuthCode(r.Context(), code)
	if err != nil {
		log.Debugf("MFA gate: auth code lookup skipped: %v", err)
		return false
	}

	encodedUserID := dex.EncodeDexUserID(authCode.Claims.UserID, authCode.ConnectorID)

	user, err := h.mgmtStore.GetUserByUserID(r.Context(), nbstore.LockingStrengthNone, encodedUserID)
	if err != nil {
		log.Debugf("MFA gate: user lookup skipped: %v", err)
		return false
	}

	if !user.MFAEnabled || user.MFASecret == "" {
		return false
	}

	sessionID := uuid.New().String()
	h.mu.Lock()
	h.pending[sessionID] = &pendingMFA{
		redirectURL: redirectURL,
		userID:      encodedUserID,
		createdAt:   time.Now(),
	}
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "nb_mfa_session",
		Value:    sessionID,
		Path:     "/oauth2/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	log.Infof("MFA gate: TOTP verification required for user %s", authCode.Claims.Email)
	renderMFAForm(w, "")
	return true
}

func (h *Handler) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("nb_mfa_session")
	if err != nil {
		http.Error(w, "Session expired. Please log in again.", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	session, ok := h.pending[cookie.Value]
	h.mu.Unlock()

	if !ok || time.Since(session.createdAt) > 5*time.Minute {
		http.Error(w, "Session expired. Please log in again.", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" || len(code) != 6 {
		renderMFAForm(w, "Please enter a valid 6-digit code")
		return
	}

	user, err := h.mgmtStore.GetUserByUserID(r.Context(), nbstore.LockingStrengthNone, session.userID)
	if err != nil {
		renderMFAForm(w, "User not found. Please log in again.")
		return
	}

	if !mfa.ValidateCode(user.MFASecret, code) {
		renderMFAForm(w, "Invalid code. Please try again.")
		return
	}

	h.mu.Lock()
	delete(h.pending, cookie.Value)
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "nb_mfa_session",
		Value:    "",
		Path:     "/oauth2/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	mfa.SetSession(session.userID, time.Now())
	mfa.SetOIDCSession(session.userID)

	log.Infof("MFA gate: TOTP verified for user %s", session.userID)
	http.Redirect(w, r, session.redirectURL, http.StatusFound)
}

func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.mu.Lock()
		for k, v := range h.pending {
			if time.Since(v.createdAt) > 5*time.Minute {
				delete(h.pending, k)
			}
		}
		h.mu.Unlock()
	}
}

func extractCode(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("code")
}

type bufferedWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func (b *bufferedWriter) Header() http.Header     { return b.header }
func (b *bufferedWriter) Write(d []byte) (int, error) { return b.body.Write(d) }
func (b *bufferedWriter) WriteHeader(code int)     { b.statusCode = code }

func flushBuffered(w http.ResponseWriter, buf *bufferedWriter) {
	for k, vv := range buf.header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(buf.statusCode)
	_, _ = w.Write(buf.body.Bytes())
}

func renderMFAForm(w http.ResponseWriter, errorMsg string) {
	tmpl, err := template.New("mfa").Parse(mfaFormHTML)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := map[string]string{}
	if errorMsg != "" {
		data["Error"] = errorMsg
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

const mfaFormHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetBird MFA Verification</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#181a1d;color:#e4e7e9;display:flex;justify-content:center;padding-top:8vh}
.card{background:#1b1f22;border:1px solid rgba(50,54,61,.5);border-radius:12px;padding:40px;width:375px;max-width:90vw;box-shadow:0 20px 25px -5px rgba(0,0,0,.1)}
.icon{text-align:center;margin-bottom:24px}
h1{font-size:1.5rem;font-weight:500;text-align:center;margin-bottom:8px}
.sub{text-align:center;color:rgba(167,177,185,.8);font-weight:300;margin-bottom:24px}
.err{color:#f87171;background:rgba(153,27,27,.2);border:1px solid rgba(153,27,27,.5);border-radius:8px;padding:10px;text-align:center;margin-bottom:16px;font-size:.875rem}
input[type=text]{width:100%;padding:12px;font-size:1.5rem;letter-spacing:.5rem;text-align:center;background:#282c31;border:1px solid rgba(50,54,61,.8);border-radius:8px;color:#fff;outline:none}
input:focus{border-color:#f68330}
input::placeholder{letter-spacing:normal;font-size:.875rem;color:#6b7280}
.btn{width:100%;padding:12px;font-size:1rem;font-weight:500;color:#fff;background:#f68330;border:none;border-radius:8px;cursor:pointer;margin-top:12px}
.btn:hover{background:#e5721f}
</style>
</head>
<body>
<div>
<div style="text-align:center;margin-bottom:40px">
<svg width="133" height="23" viewBox="0 0 133 23" fill="none" xmlns="http://www.w3.org/2000/svg"><g clip-path="url(#nb)"><path d="M46.94 7.5c1.18 1.15 1.77 2.8 1.77 4.97v9.2h-2.57v-8.83c0-1.56-.39-2.75-1.17-3.57-.78-.83-1.84-1.24-3.19-1.24s-2.45.43-3.26 1.28c-.81.85-1.21 2.1-1.21 3.73v8.63h-2.59V6.06h2.59v2.22c.51-.79 1.21-1.41 2.09-1.85a6.3 6.3 0 0 1 2.92-.65c1.9 0 3.44.58 4.62 1.72Z" fill="#F2F2F2"/><path d="M67.1 14.83H54.63c.09 1.54.62 2.74 1.58 3.6.96.87 2.12 1.3 3.49 1.3 1.12 0 2.06-.26 2.8-.79.75-.52 1.28-1.22 1.58-2.09h2.79c-.42 1.5-1.25 2.72-2.51 3.66-1.25.94-2.81 1.42-4.67 1.42-1.48 0-2.8-.33-3.97-1-1.17-.66-2.08-1.6-2.75-2.83-.67-1.22-1-2.64-1-4.25s.33-3.03.97-4.24c.64-1.21 1.56-2.15 2.72-2.81 1.17-.65 2.51-.98 4.03-.98s2.79.33 3.93.97c1.14.64 2.02 1.53 2.64 2.66.62 1.13.93 2.41.93 3.86 0 .49-.03 1-.08 1.56Zm-3.25-4.66c-.43-.71-1.02-1.25-1.78-1.62a5.23 5.23 0 0 0-2.49-.55c-1.31 0-2.43.42-3.35 1.25-.91.84-1.43 1.99-1.57 3.48h9.85c0-.98-.22-1.84-.66-2.56Z" fill="#F2F2F2"/><path d="M73.77 8.2v9.2c0 .76.16 1.3.48 1.6.33.31.89.47 1.68.47h1.91v2.19h-2.33c-1.45 0-2.53-.33-3.25-1-1.72-.66-1.08-1.76-1.08-3.28V8.2h-2.02V6.06h2.02V2.13h2.59v3.93h4.07V8.2h-4.07Z" fill="#F2F2F2"/><path d="M85.9 6.69c1.03-.59 2.19-.89 3.51-.89 1.4 0 2.67.33 3.79 1 1.12.67 2 1.6 2.65 2.8.64 1.2.97 2.61.97 4.2s-.33 2.99-.97 4.21c-.65 1.24-1.53 2.19-2.66 2.88-1.13.69-2.39 1.03-3.77 1.03s-2.53-.29-3.54-.89c-.97-.59-1.74-1.34-2.25-2.25v2.88h-2.59V.6h2.59v8.37c.54-.93 1.31-1.69 2.33-2.28Zm7.55 4.05c-.48-.87-1.11-1.54-1.92-2-.81-.45-1.7-.68-2.66-.68s-1.83.24-2.63.7c-.81.47-1.46 1.14-1.94 2.02-.49.89-.73 1.91-.73 3.07s.24 2.21.73 3.1c.49.89 1.13 1.56 1.94 2.02.8.47 1.68.7 2.63.7s1.85-.23 2.66-.7c.8-.47 1.44-1.14 1.92-2.02.48-.89.72-1.92.72-3.12s-.24-2.2-.72-3.1Z" fill="#F2F2F2"/><path d="M100.32 3.02c-.34-.34-.51-.76-.51-1.25s.17-.91.51-1.26c.34-.34.76-.51 1.25-.51s.88.17 1.21.51c.34.34.5.76.5 1.26s-.17.91-.5 1.25c-.34.34-.74.51-1.21.51s-.91-.17-1.25-.51Zm2.51 3.04v15.6h-2.59V6.06h2.59Z" fill="#F2F2F2"/><path d="M111.77 6.52c.84-.49 1.87-.74 3.09-.74v2.68h-.69c-2.9 0-4.35 1.57-4.35 4.73v8.49h-2.59V6.06h2.59v2.53c.45-.89 1.1-1.59 1.95-2.07Z" fill="#F2F2F2"/><path d="M117.86 9.61c.64-1.2 1.53-2.14 2.66-2.8 1.13-.66 2.4-1 3.8-1 1.22 0 2.35.28 3.39.84.82.56 1.58 1.3 2.13 2.21V.6h2.62v21.07h-2.62v-2.93c-.51.93-1.27 1.7-2.28 2.29-1 .6-2.18.9-3.52.9s-2.64-.34-3.77-1.03c-1.13-.69-2.01-1.64-2.66-2.88-.64-1.24-.97-2.62-.97-4.2s.33-2.99.97-4.2Zm11.53 1.15c-.48-.87-1.11-1.54-1.92-2-.81-.47-1.7-.7-2.66-.7s-1.85.23-2.65.7c-.8.46-1.43 1.13-1.91 2-.48.89-.72 1.92-.72 3.13s.24 2.23.72 3.12c.48.89 1.11 1.56 1.91 2.02.79.47 1.68.7 2.65.7s1.85-.23 2.66-.7c.8-.47 1.44-1.14 1.92-2.02.48-.89.72-1.9.72-3.1s-.24-2.23-.72-3.13Z" fill="#F2F2F2"/><path d="M21.47.57C17.82.9 16 3 15.32 4.06L4.67 22.52h12.85L30.19.57h-8.73Z" fill="#F68330"/><path d="M17.53 22.52 0 3.93s19.82-5.33 21.75 11.29l-4.22 7.3Z" fill="#F68330"/><path d="m14.93 4.75-5.38 9.32 7.97 8.45 4.22-7.32c-.67-5.71-3.45-8.83-6.81-10.45" fill="#F35E32"/></g><defs><clipPath id="nb"><rect width="132.72" height="22.52" fill="#fff"/></clipPath></defs></svg>
</div>
<div class="card">
<div class="icon"><svg height="48" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" fill="none" r="45" stroke="#f68330" stroke-width="3"/><rect x="38" y="28" width="24" height="44" rx="4" fill="none" stroke="#f68330" stroke-width="3"/><circle cx="50" cy="58" r="5" fill="#f68330"/><line x1="44" y1="36" x2="56" y2="36" stroke="#f68330" stroke-width="2"/></svg></div>
<h1>MFA Verification</h1>
<p class="sub">Enter the 6-digit code from your authenticator app</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="POST" action="/oauth2/mfa-verify" autocomplete="off">
<input type="text" name="code" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" placeholder="000000" autofocus required oninput="this.value=this.value.replace(/[^0-9]/g,'')">
<button type="submit" class="btn">Verify</button>
</form>
</div>
</div>
<script>
var inp=document.querySelector('input[name=code]');
if(inp)inp.addEventListener('input',function(){if(this.value.length===6)this.closest('form').submit()});
</script>
</body>
</html>`
