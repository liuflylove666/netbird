package mfa

import (
	"fmt"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/types"
)

const (
	OIDCSessionTTL  = 5 * time.Minute
	OIDCTokenSkew   = time.Minute
	MaxAttempts     = 5
	LockoutDuration = 15 * time.Minute
	CleanupInterval = 30 * time.Minute
)

type sessionEntry struct {
	verifiedAt time.Time
	tokenIat   time.Time
}

type oidcSessionKey struct {
	userID     string
	contextKey string
}

type failureEntry struct {
	attempts int
	lockedAt time.Time
}

var (
	sessions   = make(map[string]sessionEntry)
	sessionsMu sync.RWMutex

	oidcSessions   = make(map[oidcSessionKey]time.Time)
	oidcSessionsMu sync.RWMutex

	failures   = make(map[string]failureEntry)
	failuresMu sync.Mutex
)

func init() {
	go cleanupLoop()
}

func cleanupLoop() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		oidcSessionsMu.Lock()
		for key, verifiedAt := range oidcSessions {
			if now.Sub(verifiedAt) > OIDCSessionTTL {
				delete(oidcSessions, key)
			}
		}
		oidcSessionsMu.Unlock()

		failuresMu.Lock()
		for uid, entry := range failures {
			if entry.attempts >= MaxAttempts && now.Sub(entry.lockedAt) > LockoutDuration {
				delete(failures, uid)
			}
		}
		failuresMu.Unlock()
	}
}

// SessionTTLFromSettings returns the MFA verification lifetime configured for
// the account. A zero duration means the MFA session is only bound to the
// current JWT login session and has no independent MFA-specific expiry.
func SessionTTLFromSettings(settings *types.Settings) time.Duration {
	if settings == nil || !settings.PeerLoginExpirationEnabled || settings.PeerLoginExpiration <= 0 {
		return 0
	}
	return settings.PeerLoginExpiration
}

// SetSession records MFA verification for a specific login session (identified by token iat).
func SetSession(userID string, tokenIat time.Time) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	sessions[userID] = sessionEntry{
		verifiedAt: time.Now(),
		tokenIat:   tokenIat,
	}
}

// IsSessionValid checks if MFA was verified for the current login session.
// tokenIat is the JWT token's issued-at time — a new login produces a new iat,
// invalidating any previous MFA verification.
func IsSessionValid(userID string, tokenIat time.Time, ttl time.Duration) bool {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	entry, ok := sessions[userID]
	if !ok {
		return false
	}
	if ttl > 0 && time.Since(entry.verifiedAt) > ttl {
		return false
	}
	return entry.tokenIat.Equal(tokenIat)
}

// ClearSession removes the MFA session for a user.
func ClearSession(userID string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	delete(sessions, userID)
}

// SetOIDCSession records that a user passed MFA during the OIDC login flow (MFA Gate).
// The session is a short-lived bridge that must be consumed by the first JWT
// issued by that OIDC flow, then it is converted into a token-iat-bound session.
func SetOIDCSession(userID, contextKey string) {
	oidcSessionsMu.Lock()
	defer oidcSessionsMu.Unlock()
	oidcSessions[newOIDCSessionKey(userID, contextKey)] = time.Now()
}

// ConsumeOIDCSession binds a recent OIDC-layer MFA verification to the JWT
// created by that login. It returns false for old sessions, zero iat values,
// or JWTs issued outside the narrow post-MFA exchange window.
func ConsumeOIDCSession(userID string, tokenIat time.Time, contextKey string) bool {
	if tokenIat.IsZero() {
		return false
	}

	now := time.Now()
	oidcSessionsMu.Lock()
	sessionKey, verifiedAt, ok := findOIDCSessionLocked(userID, contextKey)
	if !ok {
		oidcSessionsMu.Unlock()
		return false
	}
	if now.Sub(verifiedAt) > OIDCSessionTTL {
		delete(oidcSessions, sessionKey)
		oidcSessionsMu.Unlock()
		return false
	}
	if tokenIat.Before(verifiedAt.Add(-OIDCTokenSkew)) || tokenIat.After(verifiedAt.Add(OIDCSessionTTL)) {
		oidcSessionsMu.Unlock()
		return false
	}
	delete(oidcSessions, sessionKey)
	oidcSessionsMu.Unlock()

	SetSession(userID, tokenIat)
	return true
}

// ClearOIDCSession removes the OIDC MFA session for a user.
func ClearOIDCSession(userID string) {
	oidcSessionsMu.Lock()
	defer oidcSessionsMu.Unlock()
	for key := range oidcSessions {
		if key.userID == userID {
			delete(oidcSessions, key)
		}
	}
}

func newOIDCSessionKey(userID, contextKey string) oidcSessionKey {
	return oidcSessionKey{userID: userID, contextKey: contextKey}
}

func findOIDCSessionLocked(userID, contextKey string) (oidcSessionKey, time.Time, bool) {
	if contextKey != "" {
		key := newOIDCSessionKey(userID, contextKey)
		if verifiedAt, ok := oidcSessions[key]; ok {
			return key, verifiedAt, true
		}
	}

	key := newOIDCSessionKey(userID, "")
	verifiedAt, ok := oidcSessions[key]
	return key, verifiedAt, ok
}

// CheckRateLimit returns an error if the user has exceeded MFA attempt limits.
func CheckRateLimit(userID string) error {
	failuresMu.Lock()
	defer failuresMu.Unlock()
	entry := failures[userID]
	if entry.attempts >= MaxAttempts {
		if time.Since(entry.lockedAt) < LockoutDuration {
			remaining := LockoutDuration - time.Since(entry.lockedAt)
			return fmt.Errorf("too many failed attempts, try again in %d minutes", int(remaining.Minutes())+1)
		}
		delete(failures, userID)
	}
	return nil
}

// RecordFailure increments the failure counter for a user.
func RecordFailure(userID string) {
	failuresMu.Lock()
	defer failuresMu.Unlock()
	entry := failures[userID]
	entry.attempts++
	if entry.attempts >= MaxAttempts {
		entry.lockedAt = time.Now()
	}
	failures[userID] = entry
}

// ClearFailures resets the failure counter for a user.
func ClearFailures(userID string) {
	failuresMu.Lock()
	defer failuresMu.Unlock()
	delete(failures, userID)
}
