# STIG Compliance Management System

## Overview
The STIG Compliance Management System is a comprehensive tool designed to automate the Security Technical Implementation Guidelines (STIG) compliance checking and reporting process for Ubuntu systems. It consists of two main components:

1. **STIG Agent**: A lightweight agent that runs on Ubuntu endpoints to perform STIG compliance scans
2. **STIG Central Server**: A central management server that collects, analyzes, and reports on compliance data from multiple agents

## Features

### STIG Agent
- Automated STIG compliance scanning
- File permission checks
- User and group policy verification
- Service configuration analysis
- Network security checks
- Real-time reporting to central server
- Automated remediation capabilities (with approval)

### STIG Central Server
- Centralized compliance monitoring
- Web-based dashboard
- Detailed compliance reports
- Multi-system management
- API for integration
- Historical compliance tracking

## System Requirements

### STIG Central Server
- Ubuntu 20.04 LTS or newer
- Python 3.8 or newer
- 2GB RAM minimum
- 10GB free disk space
- Nginx web server
- Network connectivity (port 8000)

### STIG Agent
- Ubuntu 18.04 LTS or newer
- Python 3.8 or newer
- 512MB RAM minimum
- 1GB free disk space
- Network connectivity to central server

## Installation

### 1. STIG Central Server Installation

#### Prerequisites
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv nginx
```

#### Installation Steps
```bash
# Clone the repository
git clone https://github.com/your-repo/stig-management.git
cd stig-management

# Run the installation script
sudo ./install_central.sh
```

#### Verify Installation
```bash
# Check service status
sudo systemctl status stig-central

# Check logs
sudo journalctl -u stig-central
```

### 2. STIG Agent Installation

#### Prerequisites
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv
```

#### Installation Steps
```bash
# Clone the repository
git clone https://github.com/your-repo/stig-management.git
cd stig-management

# Configure the agent
sudo mkdir -p /etc/stig-agent
sudo nano /etc/stig-agent/config.json

# Add the following configuration (modify as needed):
{
    "central_server": {
        "url": "https://your-central-server-ip:8000",
        "api_key": "agent-key-123",
        "verify_ssl": true
    },
    "scan_interval": 3600,
    "database_path": "/var/lib/stig-agent/stig.db",
    "backup_dir": "/var/lib/stig-agent/backups",
    "log_level": "INFO",
    "scanners": {
        "file_permissions": {
            "enabled": true,
            "exclude_paths": []
        },
        "user_group": {
            "enabled": true,
            "exclude_users": []
        },
        "service": {
            "enabled": true,
            "exclude_services": []
        }
    }
}

# Run the installation script
sudo ./install.sh
```

#### Verify Installation
```bash
# Check service status
sudo systemctl status stig-agent

# Check logs
sudo journalctl -u stig-agent
```

## Configuration

### Central Server Configuration
The central server configuration file is located at `/etc/stig-central/config.json`:
```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 8000,
        "workers": 4,
        "ssl": {
            "enabled": true,
            "cert_file": "/etc/stig-central/cert.pem",
            "key_file": "/etc/stig-central/key.pem"
        }
    },
    "database": {
        "path": "/var/lib/stig-central/central.db"
    },
    "api_keys": {
        "agent-key-123": {
            "name": "Production Agent 1",
            "permissions": ["submit_results", "view_results"]
        }
    },
    "logging": {
        "level": "INFO",
        "file": "/var/log/stig-central/server.log"
    }
}
```

## Usage

### Accessing the Central Server Dashboard
1. Open a web browser
2. Navigate to `https://your-central-server-ip:8000`
3. Log in with your credentials

### Running Manual Scans
```bash
# On agent systems
sudo -u stig-agent /opt/stig-agent/venv/bin/python3 -m ubuntu_stig_agent.agent --scan
```

### Viewing Reports
1. Access the central server dashboard
2. Navigate to the Reports section
3. Select the desired system and time period

## Maintenance

### Backing Up Data
```bash
# Central Server
sudo cp /var/lib/stig-central/central.db /backup/central-$(date +%Y%m%d).db

# Agent
sudo cp /var/lib/stig-agent/stig.db /backup/agent-$(date +%Y%m%d).db
```

### Updating the System
```bash
# Pull latest changes
git pull

# Reinstall
sudo ./install.sh  # For agent
sudo ./install_central.sh  # For central server
```

## Troubleshooting

### Common Issues

1. Agent Not Connecting
```bash
# Check agent service
sudo systemctl status stig-agent

# Check connectivity
curl -k https://your-central-server-ip:8000
```

2. Central Server Not Starting
```bash
# Check service status
sudo systemctl status stig-central

# Check logs
sudo journalctl -u stig-central
```

### Log Locations
- Central Server: `/var/log/stig-central/server.log`
- Agent: `/var/log/stig-agent/agent.log`

## Uninstallation

### Remove Agent
```bash
sudo ./uninstall_agent.sh
```

### Remove Central Server
```bash
sudo ./uninstall_central.sh
```

## Security Considerations
1. Always use strong API keys
2. Keep SSL certificates up to date
3. Regularly update the system
4. Monitor logs for unauthorized access attempts
5. Use proper firewall rules

## Support
For issues and feature requests, please create an issue in the repository.

## License
 
