package mfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConsumeOIDCSessionBindsTokenSessionOnce(t *testing.T) {
	userID := "oidc-user"
	ClearSession(userID)
	ClearOIDCSession(userID)
	t.Cleanup(func() {
		ClearSession(userID)
		ClearOIDCSession(userID)
	})

	mfaContext := "login-nonce"
	SetOIDCSession(userID, mfaContext)
	tokenIat := time.Now()

	require.False(t, ConsumeOIDCSession(userID, tokenIat, "wrong-nonce"))
	require.True(t, ConsumeOIDCSession(userID, tokenIat, mfaContext))
	require.True(t, IsSessionValid(userID, tokenIat, 0))
	require.False(t, ConsumeOIDCSession(userID, tokenIat.Add(time.Second), mfaContext))
}

func TestConsumeOIDCSessionRejectsZeroAndExpiredIAT(t *testing.T) {
	userID := "expired-oidc-user"
	ClearSession(userID)
	ClearOIDCSession(userID)
	t.Cleanup(func() {
		ClearSession(userID)
		ClearOIDCSession(userID)
	})

	SetOIDCSession(userID, "")
	require.False(t, ConsumeOIDCSession(userID, time.Time{}, ""))

	oidcSessionsMu.Lock()
	oidcSessions[newOIDCSessionKey(userID, "")] = time.Now().Add(-OIDCSessionTTL - time.Second)
	oidcSessionsMu.Unlock()

	require.False(t, ConsumeOIDCSession(userID, time.Now(), ""))
	require.False(t, IsSessionValid(userID, time.Now(), 0))
}

func TestIsSessionValidUsesConfiguredTTL(t *testing.T) {
	userID := "ttl-user"
	tokenIat := time.Now()
	ClearSession(userID)
	t.Cleanup(func() {
		ClearSession(userID)
	})

	SetSession(userID, tokenIat)
	sessionsMu.Lock()
	sessions[userID] = sessionEntry{
		verifiedAt: time.Now().Add(-2 * time.Hour),
		tokenIat:   tokenIat,
	}
	sessionsMu.Unlock()

	require.True(t, IsSessionValid(userID, tokenIat, 3*time.Hour))
	require.False(t, IsSessionValid(userID, tokenIat, time.Hour))
	require.True(t, IsSessionValid(userID, tokenIat, 0))
}
