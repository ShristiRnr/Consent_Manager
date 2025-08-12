package main

import (
	"bytes"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// OAuthClientRequest represents the request to create an OAuth client
type OAuthClientRequest struct {
	AppName string   `json:"appName"`
	Scopes  []string `json:"scopes"`
}

// OAuthClientResponse represents the response when creating an OAuth client
type OAuthClientResponse struct {
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	AppName      string   `json:"appName"`
	Scopes       []string `json:"scopes"`
}

// TokenRequest represents the request to obtain an access token
type TokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
}

// TokenResponse represents the response when obtaining an access token
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func main() {
	fmt.Println("OAuth 2.0 Client Credentials Flow Full Test")
	fmt.Println("==========================================")

	// Initialize logger
	log.InitLogger()

	// 1. Generate a fiduciary token for testing
	fmt.Println("1. Generating fiduciary token...")

	// Load private key
	privateKey, err := auth.LoadPrivateKey("private.pem")
	if err != nil {
		fmt.Printf("   Error loading private key: %v\n", err)
		return
	}

	// Create a test fiduciary user
	fiduciaryUser := models.FiduciaryUser{
		ID:       uuid.New(),
		TenantID: uuid.New(), // In a real scenario, this would be an existing tenant
		Email:    "test@example.com",
		Name:     "Test Fiduciary User",
		Role:     "admin",
	}

	// Generate fiduciary token
	fiduciaryToken, err := auth.GenerateFiduciaryToken(fiduciaryUser, privateKey, time.Hour)
	if err != nil {
		fmt.Printf("   Error generating fiduciary token: %v\n", err)
		return
	}

	fmt.Printf("   Fiduciary token generated successfully\n")

	// 2. Create an OAuth client using the fiduciary token
	fmt.Println("2. Creating OAuth client...")

	clientReq := OAuthClientRequest{
		AppName: "Test OAuth App",
		Scopes:  []string{"read", "write"},
	}

	clientReqBytes, _ := json.Marshal(clientReq)
	req, _ := http.NewRequest("POST", "http://localhost:8080/api/v1/fiduciary/oauth-clients", bytes.NewBuffer(clientReqBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fiduciaryToken)

	client := &http.Client{Timeout: time.Second * 10}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("   Error creating OAuth client: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("   Response Status: %s\n", resp.Status)
	fmt.Printf("   Response Body: %s\n", string(body))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var clientResp OAuthClientResponse
		json.Unmarshal(body, &clientResp)

		// 3. Obtain an access token using the OAuth client credentials
		fmt.Println("3. Obtaining access token...")
		tokenReq := TokenRequest{
			ClientID:     clientResp.ClientID,
			ClientSecret: clientResp.ClientSecret,
			GrantType:    "client_credentials",
		}

		tokenReqBytes, _ := json.Marshal(tokenReq)
		resp, err := http.Post("http://localhost:8080/oauth/token", "application/json", bytes.NewBuffer(tokenReqBytes))
		if err != nil {
			fmt.Printf("   Error: %v\n", err)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("   Response Status: %s\n", resp.Status)
		fmt.Printf("   Response Body: %s\n", string(body))

		if resp.StatusCode == http.StatusOK {
			var tokenResp TokenResponse
			json.Unmarshal(body, &tokenResp)

			// 4. Access a protected API endpoint
			fmt.Println("4. Accessing protected API endpoint...")
			req, _ := http.NewRequest("GET", "http://localhost:8080/api/v1/public/data", nil)
			req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

			apiResp, err := client.Do(req)
			if err != nil {
				fmt.Printf("   Error: %v\n", err)
				return
			}
			defer apiResp.Body.Close()

			apiBody, _ := io.ReadAll(apiResp.Body)
			fmt.Printf("   Response Status: %s\n", apiResp.Status)
			fmt.Printf("   Response Body: %s\n", string(apiBody))
		} else {
			fmt.Println("   Failed to obtain access token")
		}
	} else {
		fmt.Println("   Failed to create OAuth client")
	}
}
