package users

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mfa"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type mfaHandler struct {
	accountManager account.Manager
}

func AddMFAEndpoints(accountManager account.Manager, router *mux.Router) {
	h := &mfaHandler{accountManager: accountManager}
	router.HandleFunc("/users/{userId}/mfa/setup", h.setupMFA).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/mfa/enable", h.enableMFA).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/mfa/disable", h.disableMFA).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/mfa/verify", h.verifyMFA).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/mfa/status", h.mfaStatus).Methods("GET", "OPTIONS")
}

type mfaSetupResponse struct {
	Secret string `json:"secret"`
	OTPURL string `json:"otp_url"`
}

type mfaCodeRequest struct {
	Code string `json:"code"`
}

type mfaStatusResponse struct {
	Enabled  bool `json:"enabled"`
	Verified bool `json:"verified"`
}

// setupMFA generates a new TOTP secret (does not enable yet)
func (h *mfaHandler) setupMFA(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]

	if userAuth.UserId != targetUserID {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "can only setup MFA for your own account"), w)
		return
	}

	userRecord, err := h.accountManager.GetStore().GetUserByUserID(r.Context(), store.LockingStrengthNone, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if userRecord.MFAEnabled {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "MFA is already enabled. Disable it first before re-setup."), w)
		return
	}

	secret, err := mfa.GenerateSecret()
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to generate MFA secret"), w)
		return
	}

	userRecord.MFASecret = secret
	if err := h.accountManager.GetStore().SaveUser(r.Context(), userRecord); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	email := userRecord.Email
	if email == "" {
		email = targetUserID
	}

	otpURL := mfa.BuildOTPAuthURL(secret, email, "NetBird")

	util.WriteJSONObject(r.Context(), w, &mfaSetupResponse{
		Secret: secret,
		OTPURL: otpURL,
	})
}

// enableMFA verifies a TOTP code and enables MFA
func (h *mfaHandler) enableMFA(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]

	if userAuth.UserId != targetUserID {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "can only enable MFA for your own account"), w)
		return
	}

	var req mfaCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	userRecord, err := h.accountManager.GetStore().GetUserByUserID(r.Context(), store.LockingStrengthNone, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if userRecord.MFASecret == "" {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "MFA has not been set up. Call setup first."), w)
		return
	}

	if err := mfa.CheckRateLimit(targetUserID); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.TooManyRequests, err.Error()), w)
		return
	}

	if !mfa.ValidateCode(userRecord.MFASecret, req.Code) {
		mfa.RecordFailure(targetUserID)
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid verification code"), w)
		return
	}

	mfa.ClearFailures(targetUserID)
	userRecord.MFAEnabled = true
	if err := h.accountManager.GetStore().SaveUser(r.Context(), userRecord); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	mfa.SetSession(targetUserID, userAuth.IssuedAt)

	util.WriteJSONObject(r.Context(), w, map[string]bool{"mfa_enabled": true})
}

// disableMFA disables MFA after verifying a TOTP code
func (h *mfaHandler) disableMFA(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]

	isSelf := userAuth.UserId == targetUserID

	if !isSelf {
		callerUser, cErr := h.accountManager.GetStore().GetUserByUserID(r.Context(), store.LockingStrengthNone, userAuth.UserId)
		if cErr != nil || !callerUser.HasAdminPower() {
			util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "only admins can disable MFA for other users"), w)
			return
		}
	}

	userRecord, err := h.accountManager.GetStore().GetUserByUserID(r.Context(), store.LockingStrengthNone, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if isSelf {
		var req mfaCodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
			return
		}

		if err := mfa.CheckRateLimit(targetUserID); err != nil {
			util.WriteError(r.Context(), status.Errorf(status.TooManyRequests, err.Error()), w)
			return
		}

		if !mfa.ValidateCode(userRecord.MFASecret, req.Code) {
			mfa.RecordFailure(targetUserID)
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid verification code"), w)
			return
		}
		mfa.ClearFailures(targetUserID)
	}

	userRecord.MFAEnabled = false
	userRecord.MFASecret = ""
	if err := h.accountManager.GetStore().SaveUser(r.Context(), userRecord); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	mfa.ClearSession(targetUserID)

	util.WriteJSONObject(r.Context(), w, map[string]bool{"mfa_enabled": false})
}

// verifyMFA verifies a TOTP code and creates an MFA session
func (h *mfaHandler) verifyMFA(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]

	if userAuth.UserId != targetUserID {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "can only verify MFA for your own account"), w)
		return
	}

	var req mfaCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	userRecord, err := h.accountManager.GetStore().GetUserByUserID(r.Context(), store.LockingStrengthNone, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !userRecord.MFAEnabled || userRecord.MFASecret == "" {
		util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "MFA is not enabled"), w)
		return
	}

	if err := mfa.CheckRateLimit(targetUserID); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.TooManyRequests, err.Error()), w)
		return
	}

	if !mfa.ValidateCode(userRecord.MFASecret, req.Code) {
		mfa.RecordFailure(targetUserID)
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid verification code"), w)
		return
	}

	mfa.ClearFailures(targetUserID)
	mfa.SetSession(targetUserID, userAuth.IssuedAt)
	mfa.SetOIDCSession(targetUserID)

	util.WriteJSONObject(r.Context(), w, map[string]bool{"verified": true})
}

// mfaStatus returns the MFA status for a user
func (h *mfaHandler) mfaStatus(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]

	if userAuth.UserId != targetUserID {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "can only check MFA status for your own account"), w)
		return
	}

	userRecord, err := h.accountManager.GetStore().GetUserByUserID(r.Context(), store.LockingStrengthNone, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, &mfaStatusResponse{
		Enabled:  userRecord.MFAEnabled,
		Verified: mfa.IsSessionValid(targetUserID, userAuth.IssuedAt) || mfa.IsOIDCSessionValid(targetUserID),
	})
}
