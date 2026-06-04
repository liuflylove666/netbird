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

	SetOIDCSession(userID)
	tokenIat := time.Now()

	require.True(t, ConsumeOIDCSession(userID, tokenIat))
	require.True(t, IsSessionValid(userID, tokenIat))
	require.False(t, ConsumeOIDCSession(userID, tokenIat.Add(time.Second)))
}

func TestConsumeOIDCSessionRejectsZeroAndExpiredIAT(t *testing.T) {
	userID := "expired-oidc-user"
	ClearSession(userID)
	ClearOIDCSession(userID)
	t.Cleanup(func() {
		ClearSession(userID)
		ClearOIDCSession(userID)
	})

	SetOIDCSession(userID)
	require.False(t, ConsumeOIDCSession(userID, time.Time{}))

	oidcSessionsMu.Lock()
	oidcSessions[userID] = time.Now().Add(-OIDCSessionTTL - time.Second)
	oidcSessionsMu.Unlock()

	require.False(t, ConsumeOIDCSession(userID, time.Now()))
	require.False(t, IsSessionValid(userID, time.Now()))
}
