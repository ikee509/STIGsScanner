#!/bin/bash

# STIG Central Server Installation Script
set -e

# Configuration
INSTALL_DIR="/opt/stig-central"
CONFIG_DIR="/etc/stig-central"
LOG_DIR="/var/log/stig-central"
DATA_DIR="/var/lib/stig-central"
SERVICE_NAME="stig-central"
PYTHON_MIN_VERSION="3.8"
USER="stig-central"
GROUP="stig-central"

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
mkdir -p $DATA_DIR

# Install dependencies
log "Installing system dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv python3-dev libssl-dev nginx

# Create virtual environment
log "Creating Python virtual environment..."
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

# Install Python dependencies
log "Installing Python dependencies..."
pip install --upgrade pip
pip install fastapi uvicorn aiosqlite jinja2 python-multipart

# Copy files
log "Installing STIG Central Server files..."
cp -r stig_central_server/* $INSTALL_DIR/
cp config.json $CONFIG_DIR/

# Generate self-signed SSL certificate if needed
if [ ! -f "$CONFIG_DIR/cert.pem" ]; then
    log "Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout $CONFIG_DIR/key.pem \
        -out $CONFIG_DIR/cert.pem \
        -days 365 \
        -subj "/CN=stig-central"
fi

# Create systemd service
log "Creating systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service << EOL
[Unit]
Description=STIG Central Management Server
After=network.target

[Service]
Type=simple
User=$USER
Group=$GROUP
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$INSTALL_DIR/venv/bin/uvicorn server:app --host 0.0.0.0 --port 8000 --ssl-keyfile $CONFIG_DIR/key.pem --ssl-certfile $CONFIG_DIR/cert.pem
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

# Configure nginx as reverse proxy
log "Configuring nginx..."
cat > /etc/nginx/sites-available/stig-central << EOL
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate $CONFIG_DIR/cert.pem;
    ssl_certificate_key $CONFIG_DIR/key.pem;

    location / {
        proxy_pass https://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

ln -sf /etc/nginx/sites-available/stig-central /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Set permissions
log "Setting permissions..."
chown -R $USER:$GROUP $INSTALL_DIR
chown -R $USER:$GROUP $CONFIG_DIR
chown -R $USER:$GROUP $LOG_DIR
chown -R $USER:$GROUP $DATA_DIR
chmod 750 $INSTALL_DIR
chmod 750 $CONFIG_DIR
chmod 750 $LOG_DIR
chmod 750 $DATA_DIR
chmod 640 $CONFIG_DIR/config.json
chmod 640 $CONFIG_DIR/*.pem

# Enable and start services
log "Enabling and starting services..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME
systemctl enable nginx
systemctl restart nginx

log "Installation complete!" 