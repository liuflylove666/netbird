package mfa

import (
	"fmt"
	"sync"
	"time"
)

const (
	SessionTTL       = 12 * time.Hour
	MaxAttempts      = 5
	LockoutDuration  = 15 * time.Minute
	CleanupInterval  = 30 * time.Minute
)

type sessionEntry struct {
	verifiedAt time.Time
	tokenIat   time.Time
}

type failureEntry struct {
	attempts int
	lockedAt time.Time
}

var (
	sessions   = make(map[string]sessionEntry)
	sessionsMu sync.RWMutex

	oidcSessions   = make(map[string]time.Time)
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
		sessionsMu.Lock()
		for uid, entry := range sessions {
			if now.Sub(entry.verifiedAt) > SessionTTL {
				delete(sessions, uid)
			}
		}
		sessionsMu.Unlock()

		oidcSessionsMu.Lock()
		for uid, verifiedAt := range oidcSessions {
			if now.Sub(verifiedAt) > SessionTTL {
				delete(oidcSessions, uid)
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
func IsSessionValid(userID string, tokenIat time.Time) bool {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	entry, ok := sessions[userID]
	if !ok {
		return false
	}
	if time.Since(entry.verifiedAt) > SessionTTL {
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
// Unlike SetSession, this is not tied to a specific JWT iat — it covers the entire
// OIDC login and persists for SessionTTL.
func SetOIDCSession(userID string) {
	oidcSessionsMu.Lock()
	defer oidcSessionsMu.Unlock()
	oidcSessions[userID] = time.Now()
}

// IsOIDCSessionValid checks if the user recently passed MFA at the OIDC layer.
func IsOIDCSessionValid(userID string) bool {
	oidcSessionsMu.RLock()
	defer oidcSessionsMu.RUnlock()
	verifiedAt, ok := oidcSessions[userID]
	if !ok {
		return false
	}
	return time.Since(verifiedAt) <= SessionTTL
}

// ClearOIDCSession removes the OIDC MFA session for a user.
func ClearOIDCSession(userID string) {
	oidcSessionsMu.Lock()
	defer oidcSessionsMu.Unlock()
	delete(oidcSessions, userID)
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
