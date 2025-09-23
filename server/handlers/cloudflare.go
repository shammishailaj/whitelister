package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"whitelister/utils"
)

type Cloudflare struct {
	l *log.Logger
}

type CloudflareRequest struct {
	FirewallID      string `json:"firewallId"`      // Hostinger firewall ID to add rules to
	HostingerAPIKey string `json:"hostingerApiKey"` // Deprecated - use KeyID instead
	KeyID           string `json:"keyId"`           // New secure key ID approach
	Protocol        string `json:"protocol"`
	Description     string `json:"description"`
}

type CloudflareIPResponse struct {
	Success bool `json:"success"`
	Result  struct {
		IPv4Cidrs []string `json:"ipv4_cidrs"`
		IPv6Cidrs []string `json:"ipv6_cidrs"`
	} `json:"result"`
}

// Note: HostingerFirewallRule and related types are defined in hostinger.go

func NewCloudflare(l *log.Logger) *Cloudflare {
	return &Cloudflare{
		l: l,
	}
}

func (c *Cloudflare) WhitelistCloudflare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CloudflareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.l.Error("Error decoding request:", err)
		utils.SendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.FirewallID == "" {
		utils.SendErrorResponse(w, "Missing required field: firewallId", http.StatusBadRequest)
		return
	}

	// Use API key from request, key ID, or config
	keyManager := NewKeyManager(c.l)
	apiKey := req.HostingerAPIKey
	if apiKey == "" && req.KeyID != "" {
		apiKey = keyManager.GetHostingerAPIKey(req.KeyID)
	}
	if apiKey == "" {
		apiKey = keyManager.GetHostingerAPIKey("") // Get first available key
	}
	if apiKey == "" {
		utils.SendErrorResponse(w, "Hostinger API key is required", http.StatusBadRequest)
		return
	}

	// Fetch Cloudflare IPs
	cloudflareIPs, err := c.fetchCloudflareIPs()
	if err != nil {
		c.l.Error("Error fetching Cloudflare IPs:", err)
		utils.SendErrorResponse(w, "Failed to fetch Cloudflare IP ranges", http.StatusInternalServerError)
		return
	}

	// Create request with API key for firewall rules
	reqWithAPI := CloudflareRequest{
		FirewallID:      req.FirewallID,
		HostingerAPIKey: apiKey,
		Protocol:        req.Protocol,
		Description:     req.Description,
	}

	// Add firewall rules to Hostinger firewall
	addedRules, err := c.addFirewallRules(reqWithAPI, cloudflareIPs)
	if err != nil {
		c.l.Error("Error adding firewall rules:", err)
		utils.SendErrorResponse(w, fmt.Sprintf("Failed to add firewall rules: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Successfully whitelisted %d Cloudflare IP ranges", len(addedRules)),
		"details": fmt.Sprintf("Added %d firewall rules to firewall %s", len(addedRules), req.FirewallID),
		"rules_added": len(addedRules),
		"firewall_id": req.FirewallID,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}

func (c *Cloudflare) fetchCloudflareIPs() ([]string, error) {
	client := resty.New()
	client.SetTimeout(30 * time.Second)

	c.l.Info("Fetching Cloudflare IP ranges...")

	resp, err := client.R().
		SetHeader("Accept", "application/json").
		Get("https://api.cloudflare.com/client/v4/ips")

	if err != nil {
		return nil, fmt.Errorf("failed to fetch Cloudflare IPs: %v", err)
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("cloudflare API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	var cfResponse CloudflareIPResponse
	if err := json.Unmarshal(resp.Body(), &cfResponse); err != nil {
		return nil, fmt.Errorf("failed to parse Cloudflare response: %v", err)
	}

	if !cfResponse.Success {
		return nil, fmt.Errorf("cloudflare API returned success=false")
	}

	// Combine IPv4 and IPv6 ranges
	allIPs := append(cfResponse.Result.IPv4Cidrs, cfResponse.Result.IPv6Cidrs...)

	c.l.Infof("Fetched %d IP ranges from Cloudflare", len(allIPs))
	return allIPs, nil
}

func (c *Cloudflare) addFirewallRules(req CloudflareRequest, ipRanges []string) ([]HostingerFirewallRule, error) {
	// Create Hostinger handler to use real API calls
	hostingerHandler := NewHostinger(c.l)

	var addedRules []HostingerFirewallRule
	var ports []string

	// Determine ports based on protocol
	switch req.Protocol {
	case "http":
		ports = []string{"80"}
	case "https":
		ports = []string{"443"}
	case "both":
		ports = []string{"80", "443"}
	default:
		ports = []string{"80", "443"}
	}

	c.l.Infof("Adding firewall rules for %d IP ranges on ports %v to firewall %s", len(ipRanges), ports, req.FirewallID)

	// Process each IP range and port combination
	for i, ipRange := range ipRanges {
		for _, port := range ports {
			rule := HostingerRuleCreateRequest{
				Action:       "ALLOW",
				Direction:    "IN",
				Protocol:     "TCP",
				Port:         port,
				Source:       "custom",
				SourceDetail: ipRange,
				Description:  fmt.Sprintf("%s - CF IP %d/%d (Port %s)", req.Description, i+1, len(ipRanges), port),
			}

			// Add the rule using real Hostinger API
			addedRule, err := hostingerHandler.addFirewallRule(req.HostingerAPIKey, req.FirewallID, rule)
			if err != nil {
				c.l.Warnf("Failed to add rule for IP %s on port %s: %v", ipRange, port, err)
				continue
			}

			if addedRule != nil {
				addedRules = append(addedRules, *addedRule)
				c.l.Debugf("Added firewall rule for %s:%s (Rule ID: %d)", ipRange, port, addedRule.ID)
			}

			// Add small delay to avoid rate limiting
			time.Sleep(100 * time.Millisecond)
		}
	}

	if len(addedRules) == 0 {
		return nil, fmt.Errorf("no firewall rules were successfully added")
	}

	c.l.Infof("Successfully added %d firewall rules to firewall %s", len(addedRules), req.FirewallID)
	return addedRules, nil
}

// ListCloudflareIPs returns the current Cloudflare IP ranges
func (c *Cloudflare) ListCloudflareIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ips, err := c.fetchCloudflareIPs()
	if err != nil {
		c.l.Error("Error fetching Cloudflare IPs:", err)
		utils.SendErrorResponse(w, "Failed to fetch Cloudflare IP ranges", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"count":   len(ips),
		"ips":     ips,
		"updated": time.Now().Format(time.RFC3339),
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}

// HealthCheck provides a health check endpoint
func (c *Cloudflare) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Test Cloudflare API connectivity
	_, err := c.fetchCloudflareIPs()
	status := "healthy"
	statusCode := http.StatusOK

	if err != nil {
		status = "unhealthy"
		statusCode = http.StatusServiceUnavailable
		c.l.Warn("Health check failed:", err)
	}

	response := map[string]interface{}{
		"status":    status,
		"service":   "cloudflare-whitelister",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err != nil {
		response["error"] = err.Error()
	}

	utils.SendJSONResponse(w, response, statusCode)
}