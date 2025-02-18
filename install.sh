#!/bin/bash

# STIG Agent Installation Script
set -e

# Configuration
INSTALL_DIR="/opt/stig-agent"
CONFIG_DIR="/etc/stig-agent"
LOG_DIR="/var/log/stig-agent"
SERVICE_NAME="stig-agent"
PYTHON_MIN_VERSION="3.8"
USER="stig-agent"
GROUP="stig-agent"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Log function
log() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root"
fi

# Check Python version
python3 -c "import sys; exit(0) if sys.version_info >= (${PYTHON_MIN_VERSION//./, }) else exit(1)" || {
    error "Python ${PYTHON_MIN_VERSION} or higher is required"
}

# Create user and group
log "Creating service user and group..."
id -u $USER &>/dev/null || useradd -r -s /bin/false -m -d $INSTALL_DIR $USER
id -g $GROUP &>/dev/null || groupadd -r $GROUP

# Create directories
log "Creating directories..."
mkdir -p $INSTALL_DIR
mkdir -p $CONFIG_DIR
mkdir -p $LOG_DIR
mkdir -p $INSTALL_DIR/backups

# Install dependencies
log "Installing system dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv python3-dev libssl-dev

# Create virtual environment
log "Creating Python virtual environment..."
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

# Install Python dependencies
log "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Copy files
log "Installing STIG agent files..."
cp -r ubuntu_stig_agent/* $INSTALL_DIR/
cp config.json $CONFIG_DIR/

# Create systemd service
log "Creating systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service << EOL
[Unit]
Description=STIG Compliance Agent
After=network.target

[Service]
Type=simple
User=$USER
Group=$GROUP
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 -m ubuntu_stig_agent.agent
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/agent.log
StandardError=append:$LOG_DIR/agent.error.log

[Install]
WantedBy=multi-user.target
EOL

# Set permissions
log "Setting permissions..."
chown -R $USER:$GROUP $INSTALL_DIR
chown -R $USER:$GROUP $CONFIG_DIR
chown -R $USER:$GROUP $LOG_DIR
chmod 750 $INSTALL_DIR
chmod 750 $CONFIG_DIR
chmod 750 $LOG_DIR
chmod 640 $CONFIG_DIR/config.json

# Enable and start service
log "Enabling and starting service..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

# Verify installation
log "Verifying installation..."
if systemctl is-active --quiet $SERVICE_NAME; then
    log "STIG agent installed and running successfully"
else
    error "Installation failed - service not running"
fi

# Create uninstall script
log "Creating uninstall script..."
cat > $INSTALL_DIR/uninstall.sh << EOL
#!/bin/bash
set -e

# Stop and disable service
systemctl stop $SERVICE_NAME
systemctl disable $SERVICE_NAME

# Remove files
rm -rf $INSTALL_DIR
rm -rf $CONFIG_DIR
rm -rf $LOG_DIR
rm -f /etc/systemd/system/$SERVICE_NAME.service

# Remove user and group
userdel $USER
groupdel $GROUP

# Reload systemd
systemctl daemon-reload

echo "STIG agent uninstalled successfully"
EOL

chmod 750 $INSTALL_DIR/uninstall.sh

log "Installation complete!" 