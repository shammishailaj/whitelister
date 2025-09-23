package handlers

import (
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"whitelister/utils"
)

type KeyManager struct {
	l *log.Logger
}

type ServiceKey struct {
	KeyID   string `json:"key_id"`
	KeyName string `json:"key_name"`
	Service string `json:"service"`
}

type ServiceKeysResponse struct {
	Success bool         `json:"success"`
	Keys    []ServiceKey `json:"keys"`
}

func NewKeyManager(l *log.Logger) *KeyManager {
	return &KeyManager{
		l: l,
	}
}

// ListServiceKeys returns available keys for a service (without exposing actual key values)
func (k *KeyManager) ListServiceKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	service := r.URL.Query().Get("service")
	if service == "" {
		utils.SendErrorResponse(w, "Service parameter is required", http.StatusBadRequest)
		return
	}

	keys := k.getServiceKeys(service)

	response := ServiceKeysResponse{
		Success: true,
		Keys:    keys,
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}

// ListAllServices returns all available services with their keys
func (k *KeyManager) ListAllServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	services := map[string][]ServiceKey{
		"hostinger":  k.getServiceKeys("hostinger"),
		"scaleway":   k.getServiceKeys("scaleway"),
		"cloudflare": k.getServiceKeys("cloudflare"),
	}

	response := map[string]interface{}{
		"success":  true,
		"services": services,
	}

	utils.SendJSONResponse(w, response, http.StatusOK)
}

func (k *KeyManager) getServiceKeys(service string) []ServiceKey {
	var keys []ServiceKey

	serviceConfig := viper.GetStringMap("api_keys." + service)

	for _, configInterface := range serviceConfig {
		if config, ok := configInterface.(map[string]interface{}); ok {
			if keyID, exists := config["key_id"]; exists {
				if keyName, nameExists := config["key_name"]; nameExists {
					keys = append(keys, ServiceKey{
						KeyID:   keyID.(string),
						KeyName: keyName.(string),
						Service: service,
					})
				}
			}
		}
	}

	return keys
}

// GetKeyByID retrieves the actual API key for a given key ID (server-side only)
func (k *KeyManager) GetKeyByID(keyID string) (map[string]interface{}, error) {
	// Search through all services for the key ID
	services := []string{"hostinger", "scaleway", "cloudflare"}

	for _, service := range services {
		serviceConfig := viper.GetStringMap("api_keys." + service)

		for _, configInterface := range serviceConfig {
			if config, ok := configInterface.(map[string]interface{}); ok {
				if id, exists := config["key_id"]; exists && id.(string) == keyID {
					// Return the full config for this key
					result := make(map[string]interface{})
					for key, value := range config {
						result[key] = value
					}
					result["service"] = service
					return result, nil
				}
			}
		}
	}

	return nil, nil // Key not found
}

// GetHostingerAPIKey returns the API token for a given Hostinger key ID
func (k *KeyManager) GetHostingerAPIKey(keyID string) string {
	if keyID == "" {
		// Return first available key as fallback
		keys := k.getServiceKeys("hostinger")
		if len(keys) > 0 {
			keyID = keys[0].KeyID
		}
	}

	keyConfig, err := k.GetKeyByID(keyID)
	if err != nil || keyConfig == nil {
		k.l.Warnf("Failed to find Hostinger key with ID: %s", keyID)
		return ""
	}

	if apiToken, exists := keyConfig["api_token"]; exists {
		if token, ok := apiToken.(string); ok {
			return token
		}
	}

	return ""
}

// GetScalewayAPIKey returns the API credentials for a given Scaleway key ID
func (k *KeyManager) GetScalewayAPIKey(keyID string) map[string]string {
	if keyID == "" {
		// Return first available key as fallback
		keys := k.getServiceKeys("scaleway")
		if len(keys) > 0 {
			keyID = keys[0].KeyID
		}
	}

	keyConfig, err := k.GetKeyByID(keyID)
	if err != nil || keyConfig == nil {
		k.l.Warnf("Failed to find Scaleway key with ID: %s", keyID)
		return nil
	}

	result := make(map[string]string)
	if accessKey, exists := keyConfig["access_key"]; exists {
		if key, ok := accessKey.(string); ok {
			result["access_key"] = key
		}
	}
	if secretKey, exists := keyConfig["secret_key"]; exists {
		if key, ok := secretKey.(string); ok {
			result["secret_key"] = key
		}
	}
	if organization, exists := keyConfig["organization"]; exists {
		if org, ok := organization.(string); ok {
			result["organization"] = org
		}
	}
	if zone, exists := keyConfig["zone"]; exists {
		if z, ok := zone.(string); ok {
			result["zone"] = z
		}
	}

	return result
}