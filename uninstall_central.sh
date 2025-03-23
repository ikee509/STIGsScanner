#!/bin/bash

# STIG Central Server Uninstall Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SERVICE_NAME="stig-central"
INSTALL_DIR="/opt/stig-central"
CONFIG_DIR="/etc/stig-central"
LOG_DIR="/var/log/stig-central"
DATA_DIR="/var/lib/stig-central"
USER="stig-central"
GROUP="stig-central"

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

# Confirm uninstallation
read -p "Are you sure you want to uninstall the STIG Central Server? This will remove all data and configurations. (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    exit 1
fi

# Stop and disable services
log "Stopping and disabling STIG Central Server services..."
systemctl stop $SERVICE_NAME || warn "Main service was not running"
systemctl disable $SERVICE_NAME || warn "Main service was not enabled"
rm -f /etc/systemd/system/$SERVICE_NAME.service
systemctl daemon-reload

# Remove nginx configuration
log "Removing nginx configuration..."
rm -f /etc/nginx/sites-enabled/stig-central
rm -f /etc/nginx/sites-available/stig-central
systemctl restart nginx

# Backup configuration and data if requested
read -p "Would you like to backup the configuration and database before removing? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    BACKUP_DIR="/root/stig-central-backup-$(date +%Y%m%d_%H%M%S)"
    log "Creating backup in $BACKUP_DIR..."
    mkdir -p $BACKUP_DIR
    [ -d "$CONFIG_DIR" ] && cp -r $CONFIG_DIR $BACKUP_DIR/
    [ -d "$DATA_DIR" ] && cp -r $DATA_DIR $BACKUP_DIR/
fi

# Remove directories
log "Removing STIG Central Server files..."
rm -rf $INSTALL_DIR
rm -rf $CONFIG_DIR
rm -rf $LOG_DIR
rm -rf $DATA_DIR

# Remove user and group
log "Removing service user and group..."
userdel $USER || warn "User $USER did not exist"
groupdel $GROUP || warn "Group $GROUP did not exist"

# Clean up Python virtual environment
log "Cleaning up Python environment..."
rm -rf $INSTALL_DIR/venv

# Remove Docker containers and images if they exist
if command -v docker &> /dev/null; then
    log "Cleaning up Docker resources..."
    docker-compose down -v || warn "No Docker containers to remove"
    docker rmi stig-central:latest || warn "No Docker image to remove"
fi

log "STIG Central Server has been uninstalled successfully!"
if [[ $REPLY =~ ^[Yy]$ ]]
then
    log "Configuration and data backup saved to $BACKUP_DIR"
fi

warn "Note: This script did not remove installed dependencies (Python, nginx, etc.)"
warn "If you want to remove these, please do so manually using your package manager." 