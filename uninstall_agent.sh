#!/bin/bash

# STIG Agent Uninstall Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SERVICE_NAME="stig-agent"
INSTALL_DIR="/opt/stig-agent"
CONFIG_DIR="/etc/stig-agent"
LOG_DIR="/var/log/stig-agent"
DATA_DIR="/var/lib/stig-agent"
USER="stig-agent"
GROUP="stig-agent"

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
read -p "Are you sure you want to uninstall the STIG Agent? This will remove all data and configurations. (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    exit 1
fi

# Stop and disable service
log "Stopping and disabling STIG Agent service..."
systemctl stop $SERVICE_NAME || warn "Service was not running"
systemctl disable $SERVICE_NAME || warn "Service was not enabled"
rm -f /etc/systemd/system/$SERVICE_NAME.service
systemctl daemon-reload

# Backup configuration if requested
read -p "Would you like to backup the configuration before removing? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    BACKUP_DIR="/root/stig-agent-backup-$(date +%Y%m%d_%H%M%S)"
    log "Creating backup in $BACKUP_DIR..."
    mkdir -p $BACKUP_DIR
    [ -d "$CONFIG_DIR" ] && cp -r $CONFIG_DIR $BACKUP_DIR/
    [ -d "$DATA_DIR" ] && cp -r $DATA_DIR $BACKUP_DIR/
fi

# Remove directories
log "Removing STIG Agent files..."
rm -rf $INSTALL_DIR
rm -rf $CONFIG_DIR
rm -rf $LOG_DIR
rm -rf $DATA_DIR

# Remove user and group
log "Removing service user and group..."
userdel $USER || warn "User $USER did not exist"
groupdel $GROUP || warn "Group $GROUP did not exist"

log "STIG Agent has been uninstalled successfully!"
if [[ $REPLY =~ ^[Yy]$ ]]
then
    log "Configuration backup saved to $BACKUP_DIR"
fi 