package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	CustomPort      string `json:"customPort,omitempty"`      // Custom port number
	SSHMode         bool   `json:"sshMode,omitempty"`         // SSH mode flag
	SSHIPs          []string `json:"sshIPs,omitempty"`       // IPs for SSH access
	CleanupExisting bool   `json:"cleanupExisting,omitempty"` // Remove existing rules first
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

type FirewallRuleResult struct {
	AddedRules   []HostingerFirewallRule `json:"added_rules"`
	DeletedCount int                     `json:"deleted_count"`
}

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

	var ipRanges []string
	var ipType string

	// Determine which IPs to use
	if req.SSHMode && len(req.SSHIPs) > 0 {
		ipRanges = req.SSHIPs
		ipType = "SSH"
		c.l.Infof("SSH mode: Using %d provided IP addresses", len(ipRanges))
	} else if req.CustomPort != "" && len(req.SSHIPs) > 0 {
		ipRanges = req.SSHIPs
		ipType = "Custom"
		c.l.Infof("Custom port mode: Using %d provided IP addresses for port %s", len(ipRanges), req.CustomPort)
	} else if req.SSHMode || req.CustomPort != "" {
		// For SSH or custom port without specific IPs, we shouldn't use Cloudflare IPs
		utils.SendErrorResponse(w, "SSH mode or custom port requires specific IP addresses", http.StatusBadRequest)
		return
	} else {
		// Fetch Cloudflare IPs for standard HTTP/HTTPS
		cloudflareIPs, err := c.fetchCloudflareIPs()
		if err != nil {
			c.l.Error("Error fetching Cloudflare IPs:", err)
			utils.SendErrorResponse(w, "Failed to fetch Cloudflare IP ranges", http.StatusInternalServerError)
			return
		}
		ipRanges = cloudflareIPs
		ipType = "Cloudflare"
	}

	// Create request with API key for firewall rules
	reqWithAPI := CloudflareRequest{
		FirewallID:      req.FirewallID,
		HostingerAPIKey: apiKey,
		Protocol:        req.Protocol,
		CustomPort:      req.CustomPort,
		SSHMode:         req.SSHMode,
		SSHIPs:          req.SSHIPs,
		CleanupExisting: req.CleanupExisting,
		Description:     req.Description,
	}

	// Add firewall rules to Hostinger firewall
	result, err := c.addFirewallRules(reqWithAPI, ipRanges)
	if err != nil {
		c.l.Error("Error adding firewall rules:", err)
		utils.SendErrorResponse(w, fmt.Sprintf("Failed to add firewall rules: %v", err), http.StatusInternalServerError)
		return
	}

	// Create response message
	var message string
	if req.SSHMode {
		message = fmt.Sprintf("Successfully whitelisted %d SSH IP addresses", len(result.AddedRules))
	} else if req.CustomPort != "" {
		message = fmt.Sprintf("Successfully whitelisted %d IP addresses for port %s", len(result.AddedRules), req.CustomPort)
	} else {
		message = fmt.Sprintf("Successfully whitelisted %d %s IP ranges", len(result.AddedRules), ipType)
	}

	response := map[string]interface{}{
		"success":      true,
		"message":      message,
		"details":      fmt.Sprintf("Added %d firewall rules to firewall %s", len(result.AddedRules), req.FirewallID),
		"rules_added":  len(result.AddedRules),
		"firewall_id":  req.FirewallID,
		"ip_type":      ipType,
		"timestamp":    time.Now().Format(time.RFC3339),
	}

	if result.DeletedCount > 0 {
		response["rules_deleted"] = result.DeletedCount
		response["details"] = fmt.Sprintf("Deleted %d existing rules, added %d new firewall rules to firewall %s",
			result.DeletedCount, len(result.AddedRules), req.FirewallID)
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

func (c *Cloudflare) addFirewallRules(req CloudflareRequest, ipRanges []string) (*FirewallRuleResult, error) {
	// Create Hostinger handler to use real API calls
	hostingerHandler := NewHostinger(c.l)

	var addedRules []HostingerFirewallRule
	var ports []string
	var deletedCount int

	// Determine ports based on mode and protocol
	if req.SSHMode {
		ports = []string{"22"}
		c.l.Info("SSH mode: Adding rules for port 22")
	} else if req.CustomPort != "" {
		ports = []string{req.CustomPort}
		c.l.Infof("Custom port mode: Adding rules for port %s", req.CustomPort)
	} else {
		// Standard HTTP/HTTPS modes
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
	}

	// Clean up existing rules if requested
	if req.CleanupExisting {
		c.l.Info("Cleaning up existing rules for the specified ports...")
		for _, port := range ports {
			deleted, err := hostingerHandler.DeleteRulesByPort(req.HostingerAPIKey, req.FirewallID, port)
			if err != nil {
				c.l.Warnf("Failed to cleanup rules for port %s: %v", port, err)
			} else {
				deletedCount += deleted
				c.l.Infof("Deleted %d existing rules for port %s", deleted, port)
			}
		}
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
	if deletedCount > 0 {
		c.l.Infof("Deleted %d existing rules before adding new ones", deletedCount)
	}

	return &FirewallRuleResult{
		AddedRules:   addedRules,
		DeletedCount: deletedCount,
	}, nil
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

// GetPublicIP returns the user's public IP address
func (c *Cloudflare) GetPublicIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Try to get IP from X-Forwarded-For header first (if behind proxy)
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Real-IP")
	}
	if clientIP == "" {
		// Get IP from RemoteAddr
		clientIP = r.RemoteAddr
		// Remove port if present
		if colonPos := strings.LastIndex(clientIP, ":"); colonPos != -1 {
			clientIP = clientIP[:colonPos]
		}
	} else {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if commaPos := strings.Index(clientIP, ","); commaPos != -1 {
			clientIP = strings.TrimSpace(clientIP[:commaPos])
		}
	}

	// Also fetch external IP as backup
	externalIP, err := c.fetchExternalIP()

	response := map[string]interface{}{
		"success":    true,
		"client_ip":  clientIP,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	if err == nil && externalIP != "" {
		response["external_ip"] = externalIP
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}

// fetchExternalIP fetches the external IP from a reliable service
func (c *Cloudflare) fetchExternalIP() (string, error) {
	client := resty.New()
	client.SetTimeout(10 * time.Second)

	resp, err := client.R().Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}

	if resp.StatusCode() != 200 {
		return "", fmt.Errorf("failed to get external IP: status %d", resp.StatusCode())
	}

	ip := strings.TrimSpace(resp.String())
	return ip, nil
}