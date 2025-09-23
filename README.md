# Whitelister
A powerful tool to whitelist Cloudflare IPs on your Hostinger VPS servers with a beautiful web interface.

## Features

- 🌐 **Beautiful Web UI** - Modern, responsive interface for easy management
- ☁️ **Cloudflare Integration** - Automatically fetches current Cloudflare IP ranges
- 🔧 **Hostinger VPS Support** - Direct integration with Hostinger VPS firewall management
- 🔄 **Real-time Updates** - Always uses the latest Cloudflare IP ranges
- 📊 **Server Management** - List and manage your Hostinger VPS servers
- 🛡️ **Firewall Rules** - Automated firewall rule creation and management

## Requirements

- Go 1.14+
- Hostinger VPS account with API access
- Valid Hostinger API key

## Getting Started

### Building the Application

```bash
go build ./cmd/whitelister
```

### Running the Application

```bash
./whitelister
```

The application will start on `http://localhost:8084` (or the port configured in config/app.yml)

### Using the Web Interface

1. Open your browser and navigate to `http://localhost:8084`
2. Enter your Hostinger API key (or leave blank to use config-based key)
3. Click "Test Connection & Load Servers" to load your Hostinger firewalls
4. Select an existing firewall or create a new one
5. Choose the protocol (HTTP, HTTPS, or both)
6. Click "Whitelist Cloudflare IPs" to apply the firewall rules

### API Key Configuration

You can configure API keys in the `config/app.yml` file:

```yaml
api_keys:
  hostinger: "your-hostinger-api-token-here"
  scaleway:
    access_key: "your-scaleway-access-key"
    secret_key: "your-scaleway-secret-key"
    organization: "your-scaleway-org-id"
```

If API keys are configured in the file, you can leave the web form fields blank.

## API Endpoints

### Web UI
- `GET /` - Main web interface

### Health & Info
- `GET /ping` - Application version and health check
- `GET /api/health` - Service health status

### Cloudflare Integration
- `GET /api/cloudflare/ips` - Get current Cloudflare IP ranges
- `POST /api/whitelist/cloudflare` - Whitelist Cloudflare IPs on Hostinger VPS

### Hostinger Firewall Management
- `POST /api/hostinger/firewalls` - List available firewalls
- `POST /api/hostinger/firewall/create` - Create a new firewall
- `POST /api/hostinger/firewall/rules` - List firewall rules
- `POST /api/hostinger/test` - Test API connection

## Configuration

The application uses configuration files in the `config/` directory:
- `app.yml` - Default configuration
- `app.local.yml` - Local development overrides
- `app.dev.yml` - Development environment settings

## API Request Examples

### Whitelist Cloudflare IPs
```bash
curl -X POST http://localhost:8084/api/whitelist/cloudflare \
  -H "Content-Type: application/json" \
  -d '{
    "firewallId": "123",
    "hostingerApiKey": "your-api-key",
    "protocol": "both",
    "description": "Cloudflare IP whitelist"
  }'
```

### Get Cloudflare IPs
```bash
curl http://localhost:8084/api/cloudflare/ips
```

### List Hostinger Firewalls
```bash
curl -X POST http://localhost:8084/api/hostinger/firewalls \
  -H "Content-Type: application/json" \
  -d '{"apiKey": "your-hostinger-api-key"}'
```

### Create Hostinger Firewall
```bash
curl -X POST http://localhost:8084/api/hostinger/firewall/create \
  -H "Content-Type: application/json" \
  -d '{
    "apiKey": "your-hostinger-api-key",
    "name": "Cloudflare-Whitelist",
    "description": "Firewall for Cloudflare IP ranges"
  }'
```

## Important Notes

✅ **Real API Integration**: This tool now uses the real Hostinger API endpoints from their official documentation. You need a valid Hostinger API token to use the firewall management features.

🔐 **Security**: Never commit your API keys to version control. Use environment variables or secure configuration management.

📝 **Cloudflare IPs**: The tool automatically fetches the most current list of Cloudflare IP ranges from their official API.

## Legacy Features (Scaleway)

The application also includes legacy support for Scaleway:
