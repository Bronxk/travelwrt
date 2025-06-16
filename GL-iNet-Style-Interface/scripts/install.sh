#!/bin/sh
# GL.iNet Style Interface - Automatic Installer
# This script automates the installation process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PACKAGE_URL="https://github.com/your-repo/releases/download/v1.0.0/luci-app-glinet-style_1.0.0_all.ipk"
PACKAGE_NAME="luci-app-glinet-style"
MIN_FLASH_KB=2048  # 2MB minimum free space
MIN_RAM_KB=65536   # 64MB minimum RAM

# Functions
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_root() {
    if [ "$(id -u)" != "0" ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

check_openwrt() {
    if [ ! -f /etc/openwrt_release ]; then
        print_error "This doesn't appear to be an OpenWrt system"
        exit 1
    fi
    
    . /etc/openwrt_release
    print_status "OpenWrt version: $DISTRIB_DESCRIPTION"
}

check_system_requirements() {
    print_status "Checking system requirements..."
    
    # Check RAM
    total_ram=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    if [ "$total_ram" -lt "$MIN_RAM_KB" ]; then
        print_error "Insufficient RAM: ${total_ram}KB (need ${MIN_RAM_KB}KB)"
        exit 1
    fi
    print_status "RAM: ${total_ram}KB ✓"
    
    # Check flash storage
    available_flash=$(df /overlay | awk 'NR==2 {print $4}')
    if [ "$available_flash" -lt "$MIN_FLASH_KB" ]; then
        print_error "Insufficient storage: ${available_flash}KB (need ${MIN_FLASH_KB}KB)"
        exit 1
    fi
    print_status "Available storage: ${available_flash}KB ✓"
}

check_internet() {
    print_status "Checking internet connection..."
    if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        print_error "No internet connection"
        print_warning "Trying to ping openwrt.org..."
        if ! ping -c 1 -W 3 openwrt.org >/dev/null 2>&1; then
            print_error "Cannot reach internet. Please check your connection."
            exit 1
        fi
    fi
    print_status "Internet connection ✓"
}

backup_config() {
    print_status "Creating configuration backup..."
    backup_file="/tmp/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    sysupgrade -b "$backup_file" 2>/dev/null || true
    print_status "Backup saved to: $backup_file"
}

install_dependencies() {
    print_status "Updating package lists..."
    opkg update || {
        print_error "Failed to update package lists"
        exit 1
    }
    
    print_status "Installing dependencies..."
    deps="uhttpd uhttpd-mod-lua lua luci-base luci-lib-jsonc luci-lib-nixio"
    
    for dep in $deps; do
        if ! opkg list-installed | grep -q "^$dep "; then
            print_status "Installing $dep..."
            opkg install "$dep" || {
                print_error "Failed to install $dep"
                exit 1
            }
        else
            print_status "$dep already installed ✓"
        fi
    done
}

download_package() {
    print_status "Downloading GL.iNet interface package..."
    
    cd /tmp
    rm -f luci-app-glinet-style*.ipk
    
    if command -v wget >/dev/null 2>&1; then
        wget -O luci-app-glinet-style.ipk "$PACKAGE_URL" || {
            print_error "Failed to download package"
            exit 1
        }
    elif command -v curl >/dev/null 2>&1; then
        curl -L -o luci-app-glinet-style.ipk "$PACKAGE_URL" || {
            print_error "Failed to download package"
            exit 1
        }
    else
        print_error "Neither wget nor curl is available"
        exit 1
    fi
    
    print_status "Package downloaded successfully"
}

install_package() {
    print_status "Installing GL.iNet interface..."
    
    # Remove old version if exists
    if opkg list-installed | grep -q "^$PACKAGE_NAME "; then
        print_warning "Removing old version..."
        opkg remove "$PACKAGE_NAME" 2>/dev/null || true
    fi
    
    # Install new package
    opkg install /tmp/luci-app-glinet-style.ipk || {
        print_error "Failed to install package"
        print_warning "Trying with --force-depends..."
        opkg install --force-depends /tmp/luci-app-glinet-style.ipk || {
            print_error "Installation failed completely"
            exit 1
        }
    }
    
    print_status "Package installed successfully"
}

configure_services() {
    print_status "Configuring services..."
    
    # Enable and start GL.iNet interface
    /etc/init.d/glinet-interface enable || true
    /etc/init.d/glinet-interface start || {
        print_warning "Failed to start glinet-interface service"
    }
    
    # Restart uhttpd
    /etc/init.d/uhttpd restart || {
        print_error "Failed to restart web server"
        exit 1
    }
    
    print_status "Services configured"
}

configure_firewall() {
    print_status "Configuring firewall..."
    
    # Add firewall rules for web interface
    uci -q batch <<-EOF
        add firewall rule
        set firewall.@rule[-1].name='Allow-GLiNet-Web'
        set firewall.@rule[-1].src='lan'
        set firewall.@rule[-1].proto='tcp'
        set firewall.@rule[-1].dest_port='80'
        set firewall.@rule[-1].target='ACCEPT'
        
        add firewall rule
        set firewall.@rule[-1].name='Allow-GLiNet-WebSocket'
        set firewall.@rule[-1].src='lan'
        set firewall.@rule[-1].proto='tcp'
        set firewall.@rule[-1].dest_port='8081'
        set firewall.@rule[-1].target='ACCEPT'
        
        commit firewall
EOF
    
    /etc/init.d/firewall reload 2>/dev/null || true
    print_status "Firewall configured"
}

test_installation() {
    print_status "Testing installation..."
    
    # Check if service is running
    if ps | grep -q "[g]linet-interface"; then
        print_status "GL.iNet interface service is running ✓"
    else
        print_warning "GL.iNet interface service is not running"
    fi
    
    # Check if web server is responding
    if wget -q -O /dev/null http://127.0.0.1/index.html 2>/dev/null; then
        print_status "Web interface is responding ✓"
    else
        print_warning "Web interface is not responding"
    fi
}

print_success() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        GL.iNet Interface Installed Successfully!       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Access your router at:"
    echo -e "  ${GREEN}http://$(uci get network.lan.ipaddr 2>/dev/null || echo "192.168.1.1")${NC}"
    echo ""
    echo "Default login credentials:"
    echo -e "  Username: ${YELLOW}admin${NC}"
    echo -e "  Password: ${YELLOW}admin${NC}"
    echo ""
    echo -e "${RED}⚠️  IMPORTANT: Change the default password immediately!${NC}"
    echo ""
    echo "If you encounter any issues:"
    echo "  - Check logs: logread | grep glinet"
    echo "  - Restart service: /etc/init.d/glinet-interface restart"
    echo "  - Visit: https://github.com/your-repo/glinet-style/wiki"
}

cleanup() {
    rm -f /tmp/luci-app-glinet-style.ipk 2>/dev/null || true
}

# Main installation flow
main() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       GL.iNet Style Interface Installer v1.0.0         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Pre-installation checks
    check_root
    check_openwrt
    check_system_requirements
    check_internet
    
    # Ask for confirmation
    echo ""
    print_warning "This will install GL.iNet Style Interface on your router"
    printf "Do you want to continue? [Y/n] "
    read -r response
    case "$response" in
        [nN][oO]|[nN])
            echo "Installation cancelled."
            exit 0
            ;;
    esac
    
    # Create backup
    printf "Create configuration backup? [Y/n] "
    read -r response
    case "$response" in
        [nN][oO]|[nN])
            print_warning "Skipping backup..."
            ;;
        *)
            backup_config
            ;;
    esac
    
    # Installation
    echo ""
    install_dependencies
    download_package
    install_package
    configure_services
    configure_firewall
    test_installation
    
    # Cleanup
    cleanup
    
    # Show success message
    print_success
}

# Trap errors and cleanup
trap 'print_error "Installation failed!"; cleanup; exit 1' ERR

# Run main installation
main "$@"

# Exit successfully
exit 0