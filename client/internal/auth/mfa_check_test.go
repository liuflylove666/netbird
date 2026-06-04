package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIsMFARequiredReturnsStatusErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	user, required, err := isMFARequired(server.URL, "jwt")

	require.Error(t, err)
	require.Nil(t, user)
	require.False(t, required)
}

func TestIsMFARequiredReturnsRequiredUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/users/current", r.URL.Path)
		require.Equal(t, "Bearer jwt", r.Header.Get("Authorization"))
		require.NoError(t, json.NewEncoder(w).Encode(&mfaUserInfo{
			ID:          "user-id",
			MFAEnabled:  true,
			MFARequired: true,
		}))
	}))
	defer server.Close()

	user, required, err := isMFARequired(server.URL, "jwt")

	require.NoError(t, err)
	require.True(t, required)
	require.Equal(t, "user-id", user.ID)
}

func TestIsMFARequiredReturnsSetupRequiredError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(&mfaUserInfo{
			ID:               "user-id",
			MFASetupRequired: true,
		}))
	}))
	defer server.Close()

	user, required, err := isMFARequired(server.URL, "jwt")

	require.Error(t, err)
	require.False(t, required)
	require.Equal(t, "user-id", user.ID)
	require.Contains(t, err.Error(), "MFA setup required")
}

func TestFetchMFAStatusRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(&mfaUserInfo{ID: "user-id"}))
	}))
	defer server.Close()

	oldClient := mfaHTTPClient
	mfaHTTPClient = &http.Client{Timeout: time.Second}
	t.Cleanup(func() {
		mfaHTTPClient = oldClient
	})

	user, err := fetchMFAStatus(server.URL, "jwt")

	require.Error(t, err)
	require.Nil(t, user)
}
