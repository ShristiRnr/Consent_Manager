package uid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

type UIDResponse struct {
	UID string `json:"uid"`
}

var (
	defaultUIDServiceURL = "http://localhost:5001/generate"
	httpClient           = &http.Client{Timeout: 5 * time.Second}
)

// GetUID calls the external UID service to generate a UID for the given input.
func GetUID(input string) (string, error) {
	uidServiceURL := os.Getenv("UID_SERVICE_URL")
	if uidServiceURL == "" {
		uidServiceURL = defaultUIDServiceURL
	}

	payload := map[string]string{"input": input}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", uidServiceURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("uid service request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("uid service returned status: %d", resp.StatusCode)
	}

	var result UIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode uid response: %w", err)
	}

	if result.UID == "" {
		return "", errors.New("uid service returned empty UID")
	}

	return result.UID, nil
}
