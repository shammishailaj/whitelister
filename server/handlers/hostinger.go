package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"whitelister/utils"
)

type Hostinger struct {
	l          *log.Logger
	keyManager *KeyManager
}

// Real Hostinger API structures based on their documentation

type HostingerFirewall struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type HostingerFirewallRule struct {
	ID          int    `json:"id"`
	Action      string `json:"action"`      // "ALLOW" or "DENY"
	Direction   string `json:"direction"`   // "IN" or "OUT"
	Protocol    string `json:"protocol"`    // "TCP", "UDP", "ICMP"
	Port        string `json:"port"`        // Port or port range
	SourceIP    string `json:"source"`      // IP or CIDR
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type HostingerFirewallListResponse struct {
	Data []HostingerFirewall `json:"data"`
}

type HostingerFirewallRulesResponse struct {
	Data []HostingerFirewallRule `json:"data"`
}

type HostingerFirewallCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type HostingerFirewallCreateResponse struct {
	Data HostingerFirewall `json:"data"`
}

type HostingerRuleCreateRequest struct {
	Action       string `json:"action"`
	Direction    string `json:"direction"`
	Protocol     string `json:"protocol"`
	Port         string `json:"port,omitempty"`
	Source       string `json:"source"`
	SourceDetail string `json:"source_detail"`
	Description  string `json:"description"`
}

type HostingerRuleCreateResponse struct {
	Data HostingerFirewallRule `json:"data"`
}

type HostingerErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

type HostingerCredentials struct {
	APIKey string `json:"apiKey"` // Deprecated - use KeyID instead
	KeyID  string `json:"keyId"`  // New secure key ID approach
}

func NewHostinger(l *log.Logger) *Hostinger {
	return &Hostinger{
		l:          l,
		keyManager: NewKeyManager(l),
	}
}

// ListFirewalls returns all firewalls for the account
func (h *Hostinger) ListFirewalls(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds HostingerCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		h.l.Error("Error decoding request:", err)
		utils.SendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	apiKey := h.getAPIKey(creds.APIKey, creds.KeyID)
	if apiKey == "" {
		utils.SendErrorResponse(w, "API key is required", http.StatusBadRequest)
		return
	}

	firewalls, err := h.fetchFirewallList(apiKey)
	if err != nil {
		h.l.Error("Error fetching firewall list:", err)
		utils.SendErrorResponse(w, fmt.Sprintf("Failed to fetch firewall list: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":   true,
		"count":     len(firewalls),
		"firewalls": firewalls,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}

// CreateFirewall creates a new firewall for Cloudflare IPs
func (h *Hostinger) CreateFirewall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		APIKey      string `json:"apiKey"`
		KeyID       string `json:"keyId"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.l.Error("Error decoding request:", err)
		utils.SendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	apiKey := h.getAPIKey(req.APIKey, req.KeyID)
	if apiKey == "" || req.Name == "" {
		utils.SendErrorResponse(w, "API key and firewall name are required", http.StatusBadRequest)
		return
	}

	firewall, err := h.createFirewall(apiKey, req.Name, req.Description)
	if err != nil {
		h.l.Error("Error creating firewall:", err)
		utils.SendErrorResponse(w, fmt.Sprintf("Failed to create firewall: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":   true,
		"firewall":  firewall,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}

// ListFirewallRules returns all firewall rules for a specific firewall
func (h *Hostinger) ListFirewallRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		APIKey     string `json:"apiKey"`
		KeyID      string `json:"keyId"`
		FirewallID string `json:"firewallId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.l.Error("Error decoding request:", err)
		utils.SendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	apiKey := h.getAPIKey(req.APIKey, req.KeyID)
	if apiKey == "" || req.FirewallID == "" {
		utils.SendErrorResponse(w, "API key and firewall ID are required", http.StatusBadRequest)
		return
	}

	rules, err := h.fetchFirewallRules(apiKey, req.FirewallID)
	if err != nil {
		h.l.Error("Error fetching firewall rules:", err)
		utils.SendErrorResponse(w, fmt.Sprintf("Failed to fetch firewall rules: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":     true,
		"count":       len(rules),
		"rules":       rules,
		"firewall_id": req.FirewallID,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}

// Helper function to get API key from request, key ID, or config
func (h *Hostinger) getAPIKey(requestAPIKey, keyID string) string {
	// If explicit API key provided (legacy support)
	if requestAPIKey != "" {
		return requestAPIKey
	}

	// If key ID provided, get API key from key manager
	if keyID != "" {
		return h.keyManager.GetHostingerAPIKey(keyID)
	}

	// Fallback to first available key from config
	return h.keyManager.GetHostingerAPIKey("")
}

// Helper function to get API base URL from config
func (h *Hostinger) getAPIBaseURL() string {
	baseURL := viper.GetString("endpoints.hostinger_api")
	if baseURL == "" {
		baseURL = "https://developers.hostinger.com/api/vps/v1"
	}
	return baseURL
}

func (h *Hostinger) fetchFirewallList(apiKey string) ([]HostingerFirewall, error) {
	client := resty.New()
	client.SetTimeout(30 * time.Second)

	h.l.Info("Fetching Hostinger firewall list...")

	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+apiKey).
		SetHeader("Accept", "application/json").
		Get(h.getAPIBaseURL() + "/firewall")

	if err != nil {
		return nil, fmt.Errorf("failed to fetch firewall list: %v", err)
	}

	if resp.StatusCode() == 401 {
		return nil, fmt.Errorf("invalid API key or unauthorized access")
	}

	if resp.StatusCode() != 200 {
		// Parse error response
		var errorResp HostingerErrorResponse
		if json.Unmarshal(resp.Body(), &errorResp) == nil {
			return nil, fmt.Errorf("hostinger API error: %s (code: %d)", errorResp.Error.Message, errorResp.Error.Code)
		}
		return nil, fmt.Errorf("hostinger API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	// The real Hostinger API returns an array directly, not wrapped in a data object
	var firewalls []HostingerFirewall
	if err := json.Unmarshal(resp.Body(), &firewalls); err != nil {
		return nil, fmt.Errorf("failed to parse firewall list response: %v", err)
	}

	h.l.Infof("Fetched %d firewalls from Hostinger", len(firewalls))
	return firewalls, nil
}

func (h *Hostinger) createFirewall(apiKey, name, description string) (*HostingerFirewall, error) {
	client := resty.New()
	client.SetTimeout(30 * time.Second)

	h.l.Infof("Creating firewall: %s", name)

	createReq := HostingerFirewallCreateRequest{
		Name:        name,
		Description: description,
	}

	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+apiKey).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBody(createReq).
		Post(h.getAPIBaseURL() + "/firewall")

	if err != nil {
		return nil, fmt.Errorf("failed to create firewall: %v", err)
	}

	if resp.StatusCode() == 401 {
		return nil, fmt.Errorf("invalid API key or unauthorized access")
	}

	if resp.StatusCode() != 201 && resp.StatusCode() != 200 {
		var errorResp HostingerErrorResponse
		if json.Unmarshal(resp.Body(), &errorResp) == nil {
			return nil, fmt.Errorf("hostinger API error: %s (code: %d)", errorResp.Error.Message, errorResp.Error.Code)
		}
		return nil, fmt.Errorf("hostinger API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	// The real API might return the firewall object directly
	var createdFirewall HostingerFirewall
	if err := json.Unmarshal(resp.Body(), &createdFirewall); err != nil {
		return nil, fmt.Errorf("failed to parse firewall create response: %v", err)
	}

	h.l.Infof("Created firewall: %s (ID: %d)", createdFirewall.Name, createdFirewall.ID)
	return &createdFirewall, nil
}

func (h *Hostinger) fetchFirewallRules(apiKey, firewallID string) ([]HostingerFirewallRule, error) {
	client := resty.New()
	client.SetTimeout(30 * time.Second)

	h.l.Infof("Fetching firewall rules for firewall %s...", firewallID)

	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+apiKey).
		SetHeader("Accept", "application/json").
		Get(fmt.Sprintf("%s/firewall/%s", h.getAPIBaseURL(), firewallID))

	if err != nil {
		return nil, fmt.Errorf("failed to fetch firewall rules: %v", err)
	}

	if resp.StatusCode() == 401 {
		return nil, fmt.Errorf("invalid API key or unauthorized access")
	}

	if resp.StatusCode() == 404 {
		return nil, fmt.Errorf("firewall not found")
	}

	if resp.StatusCode() != 200 {
		var errorResp HostingerErrorResponse
		if json.Unmarshal(resp.Body(), &errorResp) == nil {
			return nil, fmt.Errorf("hostinger API error: %s (code: %d)", errorResp.Error.Message, errorResp.Error.Code)
		}
		return nil, fmt.Errorf("hostinger API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	// Parse firewall details to extract rules
	var firewallDetails struct {
		ID       int                     `json:"id"`
		Name     string                  `json:"name"`
		IsSynced bool                    `json:"is_synced"`
		Rules    []HostingerFirewallRule `json:"rules"`
	}
	if err := json.Unmarshal(resp.Body(), &firewallDetails); err != nil {
		return nil, fmt.Errorf("failed to parse firewall details response: %v", err)
	}

	h.l.Infof("Fetched %d firewall rules for firewall %s", len(firewallDetails.Rules), firewallID)
	return firewallDetails.Rules, nil
}

func (h *Hostinger) addFirewallRule(apiKey, firewallID string, rule HostingerRuleCreateRequest) (*HostingerFirewallRule, error) {
	client := resty.New()
	client.SetTimeout(30 * time.Second)

	h.l.Debugf("Adding firewall rule to firewall %s: %s %s %s:%s", firewallID, rule.Action, rule.Direction, rule.Source, rule.Port)

	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+apiKey).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBody(rule).
		Post(fmt.Sprintf("%s/firewall/%s/rules", h.getAPIBaseURL(), firewallID))

	if err != nil {
		return nil, fmt.Errorf("failed to add firewall rule: %v", err)
	}

	if resp.StatusCode() == 401 {
		return nil, fmt.Errorf("invalid API key or unauthorized access")
	}

	if resp.StatusCode() != 201 && resp.StatusCode() != 200 {
		var errorResp HostingerErrorResponse
		if json.Unmarshal(resp.Body(), &errorResp) == nil {
			return nil, fmt.Errorf("hostinger API error: %s (code: %d)", errorResp.Error.Message, errorResp.Error.Code)
		}
		return nil, fmt.Errorf("hostinger API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	// The real API might return rule object directly
	var createdRule HostingerFirewallRule
	if err := json.Unmarshal(resp.Body(), &createdRule); err != nil {
		return nil, fmt.Errorf("failed to parse rule create response: %v", err)
	}

	return &createdRule, nil
}

// deleteFirewallRule deletes a firewall rule
func (h *Hostinger) deleteFirewallRule(apiKey, firewallID string, ruleID int) error {
	client := resty.New()
	client.SetTimeout(30 * time.Second)

	h.l.Debugf("Deleting firewall rule %d from firewall %s", ruleID, firewallID)

	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+apiKey).
		SetHeader("Accept", "application/json").
		Delete(fmt.Sprintf("%s/firewall/%s/rules/%d", h.getAPIBaseURL(), firewallID, ruleID))

	if err != nil {
		return fmt.Errorf("failed to delete firewall rule: %v", err)
	}

	if resp.StatusCode() == 401 {
		return fmt.Errorf("invalid API key or unauthorized access")
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
		var errorResp HostingerErrorResponse
		if json.Unmarshal(resp.Body(), &errorResp) == nil {
			return fmt.Errorf("hostinger API error: %s (code: %d)", errorResp.Error.Message, errorResp.Error.Code)
		}
		return fmt.Errorf("hostinger API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	return nil
}

// DeleteRulesByPort deletes all firewall rules for a specific port
func (h *Hostinger) DeleteRulesByPort(apiKey, firewallID, port string) (int, error) {
	// Get current rules
	rules, err := h.fetchFirewallRules(apiKey, firewallID)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch current rules: %v", err)
	}

	var deletedCount int
	for _, rule := range rules {
		if rule.Port == port {
			if err := h.deleteFirewallRule(apiKey, firewallID, rule.ID); err != nil {
				h.l.Warnf("Failed to delete rule %d: %v", rule.ID, err)
				continue
			}
			deletedCount++
			h.l.Debugf("Deleted rule %d for port %s", rule.ID, port)

			// Add small delay to avoid rate limiting
			time.Sleep(100 * time.Millisecond)
		}
	}

	return deletedCount, nil
}

// TestConnection tests the connection to Hostinger API
func (h *Hostinger) TestConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds HostingerCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		h.l.Error("Error decoding request:", err)
		utils.SendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	apiKey := h.getAPIKey(creds.APIKey, creds.KeyID)
	if apiKey == "" {
		utils.SendErrorResponse(w, "API key is required", http.StatusBadRequest)
		return
	}

	// Test connection by fetching firewall list
	firewalls, err := h.fetchFirewallList(apiKey)
	status := "connected"
	statusCode := http.StatusOK

	if err != nil {
		status = "failed"
		statusCode = http.StatusBadRequest
		h.l.Warn("Hostinger connection test failed:", err)
	}

	response := map[string]interface{}{
		"success":   err == nil,
		"status":    status,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err != nil {
		response["error"] = err.Error()
	} else {
		response["firewalls_count"] = len(firewalls)
	}

	utils.SendJSONResponse(w, response, statusCode)
}

// EnableFirewall enables a firewall
func (h *Hostinger) EnableFirewall(w http.ResponseWriter, r *http.Request) {
	h.toggleFirewall(w, r, true)
}

// DisableFirewall disables a firewall
func (h *Hostinger) DisableFirewall(w http.ResponseWriter, r *http.Request) {
	h.toggleFirewall(w, r, false)
}

// toggleFirewall enables or disables a firewall
func (h *Hostinger) toggleFirewall(w http.ResponseWriter, r *http.Request, enable bool) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		APIKey     string `json:"apiKey"`
		KeyID      string `json:"keyId"`
		FirewallID string `json:"firewallId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.l.Error("Error decoding request:", err)
		utils.SendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	apiKey := h.getAPIKey(req.APIKey, req.KeyID)
	if apiKey == "" || req.FirewallID == "" {
		utils.SendErrorResponse(w, "API key and firewall ID are required", http.StatusBadRequest)
		return
	}

	action := "disable"
	if enable {
		action = "enable"
	}

	client := resty.New()
	client.SetTimeout(30 * time.Second)

	h.l.Infof("Attempting to %s firewall %s", action, req.FirewallID)

	// The actual API endpoint might be different - this is based on common patterns
	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+apiKey).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBody(map[string]interface{}{"enabled": enable}).
		Put(fmt.Sprintf("%s/firewall/%s", h.getAPIBaseURL(), req.FirewallID))

	if err != nil {
		h.l.Error("Error toggling firewall:", err)
		utils.SendErrorResponse(w, fmt.Sprintf("Failed to %s firewall: %v", action, err), http.StatusInternalServerError)
		return
	}

	if resp.StatusCode() == 401 {
		utils.SendErrorResponse(w, "Invalid API key or unauthorized access", http.StatusUnauthorized)
		return
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
		var errorResp HostingerErrorResponse
		if json.Unmarshal(resp.Body(), &errorResp) == nil {
			utils.SendErrorResponse(w, fmt.Sprintf("Hostinger API error: %s (code: %d)", errorResp.Error.Message, errorResp.Error.Code), http.StatusInternalServerError)
			return
		}
		utils.SendErrorResponse(w, fmt.Sprintf("Hostinger API returned status %d: %s", resp.StatusCode(), resp.String()), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":     true,
		"action":      action,
		"firewall_id": req.FirewallID,
		"enabled":     enable,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}