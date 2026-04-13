package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

type mfaUserInfo struct {
	ID               string `json:"id"`
	MFAEnabled       bool   `json:"mfa_enabled"`
	MFARequired      bool   `json:"mfa_required"`
	MFASetupRequired bool   `json:"mfa_setup_required"`
}

func fetchMFAStatus(mgmtBaseURL, jwtToken string) (*mfaUserInfo, error) {
	apiURL := strings.TrimRight(mgmtBaseURL, "/") + "/api/users/current"

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := mfaHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var user mfaUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &user, nil
}

func verifyMFACode(mgmtBaseURL, jwtToken, userID, code string) error {
	apiURL := strings.TrimRight(mgmtBaseURL, "/") + "/api/users/" + userID + "/mfa/verify"

	payload, _ := json.Marshal(map[string]string{"code": code})
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := mfaHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("verification failed (HTTP %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// isMFARequired returns true if the user has MFA enabled and session is unverified.
// Returns (userInfo, true) when TOTP prompt is needed, or (nil, false) on any error
// or when MFA is not required (graceful degradation for servers without MFA support).
func isMFARequired(mgmtBaseURL, jwtToken string) (*mfaUserInfo, bool) {
	user, err := fetchMFAStatus(mgmtBaseURL, jwtToken)
	if err != nil {
		log.Debugf("MFA status check skipped: %v", err)
		return nil, false
	}
	if user.MFASetupRequired {
		log.Warnf("Your administrator requires MFA but you have not set it up yet. Please enable MFA via the NetBird dashboard before connecting.")
	}
	return user, user.MFARequired
}

func mfaHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}
}
