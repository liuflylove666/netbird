package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var mfaHTTPClient = &http.Client{Timeout: 10 * time.Second}

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

	resp, err := mfaHTTPClient.Do(req)
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

	resp, err := mfaHTTPClient.Do(req)
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
// Status check failures are returned so login does not silently bypass MFA.
func isMFARequired(mgmtBaseURL, jwtToken string) (*mfaUserInfo, bool, error) {
	user, err := fetchMFAStatus(mgmtBaseURL, jwtToken)
	if err != nil {
		log.Debugf("MFA status check failed: %v", err)
		return nil, false, fmt.Errorf("check MFA status: %w", err)
	}
	if user.MFASetupRequired {
		return user, false, fmt.Errorf("MFA setup required: your administrator requires MFA, but it is not enabled for your account. Enable MFA in the NetBird dashboard before connecting")
	}
	return user, user.MFARequired, nil
}
