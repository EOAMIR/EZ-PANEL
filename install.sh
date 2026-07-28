#!/bin/bash

# =================================================================
#  Project:      EZ-Panel
#  Repository:   https://github.com/EOAMIR/EZ-PANEL
#  Script:       Automated Installation Script
# =================================================================

set -e

# --- Color Definitions ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- UI Helper Functions ---
print_banner() {
    clear
    echo -e "${CYAN}=====================================================${NC}"
    echo -e "${CYAN}${BOLD}                 EZ-PANEL INSTALLER                  ${NC}"
    echo -e "${CYAN}=====================================================${NC}"
    echo ""
}

print_step() {
    echo -e "${BOLD}${CYAN}[*] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

# --- Root Privileges Check ---
if [ "$EUID" -ne 0 ]; then
    print_banner
    print_error "Error: Root privileges are required to run this script."
    print_warning "Please execute with sudo or as root user."
    exit 1
fi

print_banner

# --- Step 1: System Update & Dependencies ---
print_step "Updating system packages..."
apt-get update -y > /dev/null 2>&1
apt-get upgrade -y > /dev/null 2>&1
print_success "System updated successfully."

print_step "Installing required dependencies (Python3, Git, Systemd)..."
apt-get install -y python3 python3-pip python3-venv git systemd > /dev/null 2>&1
print_success "Dependencies installed successfully."

# --- Step 2: Repository Setup ---
INSTALL_DIR="/opt/EZ-PANEL"
REPO_URL="https://github.com/EOAMIR/EZ-PANEL.git"

if [ -d "$INSTALL_DIR" ]; then
    print_step "Existing installation detected. Updating files..."
    cd "$INSTALL_DIR"
    git fetch --all > /dev/null 2>&1
    git reset --hard origin/main > /dev/null 2>&1
    print_success "Repository updated successfully."
else
    print_step "Cloning EZ-Panel repository..."
    git clone "$REPO_URL" "$INSTALL_DIR" > /dev/null 2>&1
    cd "$INSTALL_DIR"
    print_success "Repository cloned successfully."
fi

# --- Step 3: Python Packages Installation ---
print_step "Installing required Python packages..."
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    pip3 install -r "$INSTALL_DIR/requirements.txt" --break-system-packages > /dev/null 2>&1 || \
    pip3 install -r "$INSTALL_DIR/requirements.txt" > /dev/null 2>&1
else
    pip3 install flask requests python-telegram-bot --break-system-packages > /dev/null 2>&1 || \
    pip3 install flask requests python-telegram-bot > /dev/null 2>&1
fi
print_success "Python environment prepared successfully."

# --- Step 4: Systemd Service Configuration ---
print_step "Creating systemd service..."

SERVICE_FILE="/etc/systemd/system/ez-panel.service"

cat <<EOF > $SERVICE_FILE
[Unit]
Description=EZ-Panel Management Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/EZ-Panel.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ez-panel.service > /dev/null 2>&1
print_success "Systemd service configured successfully."

# --- Step 5: Start Service ---
print_step "Starting EZ-Panel service..."
systemctl restart ez-panel.service

sleep 2

# --- Final Check & Output ---
if systemctl is-active --quiet ez-panel.service; then
    echo ""
    echo -e "${GREEN}=====================================================${NC}"
    echo -e "${GREEN}${BOLD}      EZ-PANEL INSTALLED & STARTED SUCCESSFULLY      ${NC}"
    echo -e "${GREEN}=====================================================${NC}"
    echo ""
    echo -e " Service Status:   ${YELLOW}systemctl status ez-panel.service${NC}"
    echo -e " View Logs:        ${YELLOW}journalctl -u ez-panel.service -f${NC}"
    echo -e " Restart Service:  ${YELLOW}systemctl restart ez-panel.service${NC}"
    echo -e " Stop Service:     ${YELLOW}systemctl stop ez-panel.service${NC}"
    echo ""
else
    echo ""
    echo -e "${RED}=====================================================${NC}"
    echo -e "${RED}${BOLD}            INSTALLATION FAILED / ERROR              ${NC}"
    echo -e "${RED}=====================================================${NC}"
    echo ""
    print_error "Failed to start EZ-Panel service."
    print_warning "Check logs using: journalctl -u ez-panel.service -n 20"
    exit 1
fi
