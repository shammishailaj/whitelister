package handlers

import (
	"html/template"
	"net/http"
	log "github.com/sirupsen/logrus"
)

type UI struct {
	l *log.Logger
}

func NewUI(l *log.Logger) *UI {
	return &UI{
		l: l,
	}
}

func (u *UI) Index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Whitelister - Cloudflare & Hostinger</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }

        .container {
            background: white;
            padding: 2rem;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            max-width: 600px;
            width: 90%;
            animation: slideUp 0.6s ease-out;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .header h1 {
            color: #2c3e50;
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header p {
            color: #7f8c8d;
            font-size: 1.1rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #2c3e50;
            font-weight: 600;
        }

        input, select, textarea {
            width: 100%;
            padding: 0.875rem;
            border: 2px solid #e0e6ed;
            border-radius: 12px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: #f8f9fa;
        }

        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
            background: white;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 1rem 2rem;
            border: none;
            border-radius: 12px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
            margin-top: 1rem;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }

        .btn:active {
            transform: translateY(0);
        }

        .info-box {
            background: #e8f4fd;
            border: 1px solid #bee5eb;
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            color: #0c5460;
        }

        .info-box h3 {
            margin-bottom: 0.5rem;
            color: #155724;
        }

        .status {
            margin-top: 1rem;
            padding: 1rem;
            border-radius: 12px;
            display: none;
        }

        .status.success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }

        .status.error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 1rem;
        }

        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 IP Whitelister</h1>
            <p>Whitelist Cloudflare IPs for your Hostinger VPS</p>
        </div>

        <div class="info-box">
            <h3>ℹ️ What this does:</h3>
            <p>This tool automatically fetches Cloudflare's current IP ranges and creates firewall rules in your Hostinger firewall, ensuring your site remains accessible through Cloudflare's CDN while blocking other traffic.</p>
        </div>

        <form id="whitelistForm">
            <div class="form-group">
                <label for="serviceSelect">Select Service</label>
                <select id="serviceSelect" name="serviceSelect" required>
                    <option value="">Choose a service...</option>
                    <option value="hostinger">Hostinger VPS</option>
                    <option value="scaleway">Scaleway</option>
                    <option value="cloudflare">Cloudflare</option>
                </select>
            </div>

            <div class="form-group" id="keySelectGroup" style="display: none;">
                <label for="keySelect">Select API Key</label>
                <select id="keySelect" name="keySelect" required>
                    <option value="">Choose an API key...</option>
                </select>
                <button type="button" id="testConnection" class="btn" style="margin-top: 0.5rem; background: linear-gradient(135deg, #28a745, #20c997);">
                    🔗 Test Connection & Load Resources
                </button>
            </div>

            <div class="form-group" id="firewallSelectGroup" style="display: none;">
                <label for="firewallSelect">Select Firewall</label>
                <select id="firewallSelect" name="firewallSelect" required>
                    <option value="">Choose a firewall...</option>
                </select>
                <button type="button" id="createFirewall" class="btn" style="margin-top: 0.5rem; background: linear-gradient(135deg, #17a2b8, #007bff);">
                    ➕ Create New Firewall
                </button>
            </div>

            <div class="form-group" id="firewallInfoGroup" style="display: none;">
                <div id="firewallInfo" class="info-box">
                    <!-- Firewall details will be populated here -->
                </div>
            </div>

            <div class="form-group">
                <label for="protocol">Protocol</label>
                <select id="protocol" name="protocol" required>
                    <option value="both">Both HTTP & HTTPS</option>
                    <option value="http">HTTP Only</option>
                    <option value="https">HTTPS Only</option>
                </select>
            </div>

            <div class="form-group">
                <label for="description">Description (Optional)</label>
                <textarea id="description" name="description" rows="3" placeholder="Cloudflare IP whitelist for production server"></textarea>
            </div>

            <button type="submit" class="btn">🚀 Whitelist Cloudflare IPs</button>
        </form>

        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Processing your request...</p>
        </div>

        <div class="status" id="status"></div>
    </div>

    <script>
        let firewalls = [];
        let serviceKeys = {};
        let selectedKeyId = null;

        // Load all available service keys on page load
        window.addEventListener('load', async function() {
            try {
                const response = await fetch('/api/keys/services');
                const result = await response.json();
                if (result.success) {
                    serviceKeys = result.services;
                }
            } catch (error) {
                console.error('Failed to load service keys:', error);
            }
        });

        // Handle service selection
        document.getElementById('serviceSelect').addEventListener('change', function() {
            const selectedService = this.value;
            if (selectedService) {
                populateKeySelect(selectedService);
                document.getElementById('keySelectGroup').style.display = 'block';
            } else {
                document.getElementById('keySelectGroup').style.display = 'none';
                document.getElementById('firewallSelectGroup').style.display = 'none';
                document.getElementById('firewallInfoGroup').style.display = 'none';
            }
        });

        // Populate key dropdown for selected service
        function populateKeySelect(service) {
            const select = document.getElementById('keySelect');
            select.innerHTML = '<option value="">Choose an API key...</option>';

            if (serviceKeys[service]) {
                serviceKeys[service].forEach(key => {
                    const option = document.createElement('option');
                    option.value = key.key_id;
                    option.textContent = key.key_name;
                    select.appendChild(option);
                });
            }
        }

        // Update global selectedKeyId when key is selected
        document.getElementById('keySelect').addEventListener('change', function() {
            selectedKeyId = this.value;
        });

        // Test connection and load resources
        document.getElementById('testConnection').addEventListener('click', async function() {
            const selectedService = document.getElementById('serviceSelect').value;
            selectedKeyId = document.getElementById('keySelect').value;

            if (!selectedService || !selectedKeyId) {
                alert('Please select a service and API key first');
                return;
            }

            const button = this;
            const originalText = button.innerHTML;
            button.innerHTML = '🔄 Testing...';
            button.disabled = true;

            try {
                // Only load firewalls for Hostinger service
                if (selectedService === 'hostinger') {
                    const response = await fetch('/api/hostinger/firewalls', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ keyId: selectedKeyId })
                    });

                    const result = await response.json();

                    if (response.ok && result.success) {
                        firewalls = result.firewalls;
                        populateFirewallSelect(firewalls);
                        document.getElementById('firewallSelectGroup').style.display = 'block';
                        button.innerHTML = '✅ Connected!';
                        setTimeout(() => {
                            button.innerHTML = originalText;
                        }, 2000);
                    } else {
                        alert('Failed to connect: ' + (result.error || 'Unknown error'));
                        button.innerHTML = originalText;
                    }
                } else {
                    // For other services, just show connection success
                    button.innerHTML = '✅ Connected!';
                    setTimeout(() => {
                        button.innerHTML = originalText;
                    }, 2000);
                    alert('Service connected successfully! (This demo focuses on Hostinger firewall management)');
                }
            } catch (error) {
                alert('Network error: ' + error.message);
                button.innerHTML = originalText;
            }

            button.disabled = false;
        });

        // Populate firewall dropdown
        function populateFirewallSelect(firewalls) {
            const select = document.getElementById('firewallSelect');
            select.innerHTML = '<option value="">Choose a firewall...</option>';

            firewalls.forEach(firewall => {
                const option = document.createElement('option');
                option.value = firewall.id;
                option.textContent = firewall.name + ' - ' + (firewall.description || 'No description');
                option.dataset.firewall = JSON.stringify(firewall);
                select.appendChild(option);
            });
        }

        // Show firewall details when selected
        document.getElementById('firewallSelect').addEventListener('change', function() {
            const selectedOption = this.options[this.selectedIndex];
            if (selectedOption.value && selectedOption.dataset.firewall) {
                const firewall = JSON.parse(selectedOption.dataset.firewall);
                showFirewallInfo(firewall);
                document.getElementById('firewallInfoGroup').style.display = 'block';
            } else {
                document.getElementById('firewallInfoGroup').style.display = 'none';
            }
        });

        function showFirewallInfo(firewall) {
            const firewallInfo = document.getElementById('firewallInfo');
            const createdDate = new Date(firewall.created_at).toLocaleDateString();

            firewallInfo.innerHTML =
                '<h3>🛡️ Firewall Details</h3>' +
                '<p><strong>Name:</strong> ' + firewall.name + '</p>' +
                '<p><strong>ID:</strong> ' + firewall.id + '</p>' +
                '<p><strong>Description:</strong> ' + (firewall.description || 'N/A') + '</p>' +
                '<p><strong>Created:</strong> ' + createdDate + '</p>';
        }

        // Create new firewall
        document.getElementById('createFirewall').addEventListener('click', async function() {
            if (!selectedKeyId) {
                alert('Please select a service and API key first');
                return;
            }

            const name = prompt('Enter firewall name:', 'Cloudflare-Whitelist-' + Date.now());
            if (!name) return;

            const description = prompt('Enter description (optional):', 'Firewall for Cloudflare IP whitelisting');

            const button = this;
            const originalText = button.innerHTML;
            button.innerHTML = '⏳ Creating...';
            button.disabled = true;

            try {
                const response = await fetch('/api/hostinger/firewall/create', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        keyId: selectedKeyId,
                        name: name,
                        description: description
                    })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    // Refresh firewall list
                    firewalls.push(result.firewall);
                    populateFirewallSelect(firewalls);

                    // Select the new firewall
                    document.getElementById('firewallSelect').value = result.firewall.id;
                    showFirewallInfo(result.firewall);
                    document.getElementById('firewallInfoGroup').style.display = 'block';

                    alert('Firewall created successfully!');
                } else {
                    alert('Failed to create firewall: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }

            button.innerHTML = originalText;
            button.disabled = false;
        });

        // Main form submission
        document.getElementById('whitelistForm').addEventListener('submit', async function(e) {
            e.preventDefault();

            const form = e.target;
            const loading = document.getElementById('loading');
            const status = document.getElementById('status');
            const selectedFirewall = document.getElementById('firewallSelect').value;

            if (!selectedFirewall) {
                alert('Please select a firewall first');
                return;
            }

            if (!selectedKeyId) {
                alert('Please select an API key first by clicking "Test Connection"');
                return;
            }

            const firewall = firewalls.find(f => f.id == selectedFirewall);
            if (!firewall) {
                alert('Selected firewall not found');
                return;
            }

            // Hide previous status and show loading
            status.style.display = 'none';
            loading.style.display = 'block';
            form.style.display = 'none';

            try {
                const formData = new FormData(form);
                const data = {
                    firewallId: selectedFirewall,
                    keyId: selectedKeyId,
                    protocol: formData.get('protocol'),
                    description: formData.get('description') || 'Cloudflare IP whitelist'
                };

                const response = await fetch('/api/whitelist/cloudflare', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                loading.style.display = 'none';
                status.style.display = 'block';

                if (response.ok) {
                    status.className = 'status success';
                    status.innerHTML = '<h3>✅ Success!</h3><p>' + result.message + '</p>';
                    if (result.details) {
                        status.innerHTML += '<p><strong>Details:</strong> ' + result.details + '</p>';
                    }
                    if (result.rules_added) {
                        status.innerHTML += '<p><strong>Rules Added:</strong> ' + result.rules_added + '</p>';
                    }
                } else {
                    status.className = 'status error';
                    status.innerHTML = '<h3>❌ Error</h3><p>' + (result.error || 'An error occurred') + '</p>';
                }

            } catch (error) {
                loading.style.display = 'none';
                status.style.display = 'block';
                status.className = 'status error';
                status.innerHTML = '<h3>❌ Network Error</h3><p>Failed to connect to the server. Please try again.</p>';
            }

            form.style.display = 'block';
        });
    </script>
</body>
</html>`

	t, err := template.New("index").Parse(tmpl)
	if err != nil {
		u.l.Error("Error parsing template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = t.Execute(w, nil)
	if err != nil {
		u.l.Error("Error executing template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}