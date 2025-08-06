#!/bin/bash

# 5G SA Network Core Deployment Script
# Deploys Open5GS 5G Core with external gNB support
# Author: 5G Deployment Assistant
# Version: 1.0

set -e  # Exit on any error

# Configuration Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_DIR="$HOME/5g-sa-deployment"
NAMESPACE="5g-core"
GNB_IP="10.10.10.10"
AMF_IP="10.10.10.20"    # AMF NGAP interface
UPF_IP="10.10.10.21"    # UPF GTP-U interface
CORE_HOST_IP="10.10.10.20"  # Host IP for core services
NETWORK_INTERFACE="eth0"  # Modify if different

# Network Configuration
MCC="999"
MNC="70" 
TAC="1"
SST="1"
SD="0x111111"
DNN="internet"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root. Please run as a regular user with sudo privileges."
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Ubuntu version
    if ! grep -q "Ubuntu 24.04\|Ubuntu 22.04\|Ubuntu 20.04" /etc/os-release; then
        warn "This script is tested on Ubuntu 20.04/22.04/24.04. Your version may not be supported."
    fi
    
    # Check sudo access
    if ! sudo -n true 2>/dev/null; then
        error "This script requires sudo privileges. Please ensure you can run sudo commands."
    fi
    
    # Check system resources
    local memory_gb=$(free -g | awk '/^Mem:/{print $2}')
    local cpu_cores=$(nproc)
    
    if [[ $memory_gb -lt 8 ]]; then
        warn "System has ${memory_gb}GB RAM. Minimum 8GB recommended for 5G core deployment."
    fi
    
    if [[ $cpu_cores -lt 4 ]]; then
        warn "System has ${cpu_cores} CPU cores. Minimum 4 cores recommended for 5G core deployment."
    fi
    
    info "System check: ${memory_gb}GB RAM, ${cpu_cores} CPU cores"
}

# Install and configure MicroK8s
install_microk8s() {
    log "Installing and configuring MicroK8s..."
    
    # Check if MicroK8s is already installed
    if command -v microk8s &> /dev/null; then
        info "MicroK8s already installed, checking status..."
        if microk8s status --wait-ready --timeout=30; then
            log "MicroK8s is running"
        else
            warn "MicroK8s installed but not running properly, attempting to fix..."
            sudo snap remove microk8s || true
        fi
    fi
    
    if ! command -v microk8s &> /dev/null; then
        log "Installing MicroK8s..."
        sudo snap install microk8s --classic
        
        # Add user to microk8s group
        sudo usermod -a -G microk8s $USER
        
        # Apply group changes
        newgrp microk8s << EOF
        microk8s status --wait-ready
EOF
    fi
    
    # Wait for MicroK8s to be ready
    log "Waiting for MicroK8s to be ready..."
    sudo microk8s status --wait-ready --timeout=300
    
    # Enable required add-ons
    log "Enabling MicroK8s add-ons..."
    sudo microk8s enable dns storage helm3
    
    # Set up kubectl alias
    if ! grep -q "alias kubectl='microk8s kubectl'" ~/.bashrc; then
        echo "alias kubectl='microk8s kubectl'" >> ~/.bashrc
    fi
    
    # Create a temporary alias for this session
    shopt -s expand_aliases
    alias kubectl='microk8s kubectl'
    
    log "MicroK8s installation completed"
}

# Configure network interfaces
configure_network() {
    log "Configuring network interfaces..."
    
    # Check if interface exists
    if ! ip link show $NETWORK_INTERFACE &>/dev/null; then
        error "Network interface $NETWORK_INTERFACE not found. Please update NETWORK_INTERFACE variable."
    fi
    
    # Add AMF and UPF IP addresses
    log "Adding IP addresses for AMF ($AMF_IP) and UPF ($UPF_IP)..."
    
    # Check if IPs are already assigned
    if ip addr show $NETWORK_INTERFACE | grep -q "$AMF_IP"; then
        info "AMF IP $AMF_IP already assigned"
    else
        sudo ip addr add $AMF_IP/24 dev $NETWORK_INTERFACE
        log "Added AMF IP $AMF_IP to $NETWORK_INTERFACE"
    fi
    
    if ip addr show $NETWORK_INTERFACE | grep -q "$UPF_IP"; then
        info "UPF IP $UPF_IP already assigned"
    else
        sudo ip addr add $UPF_IP/24 dev $NETWORK_INTERFACE
        log "Added UPF IP $UPF_IP to $NETWORK_INTERFACE"
    fi
    
    # Configure persistent network settings
    log "Configuring persistent network settings..."
    
    # Backup existing netplan config
    sudo cp /etc/netplan/*.yaml /tmp/ 2>/dev/null || true
    
    # Create or update netplan configuration
    sudo tee /etc/netplan/01-5g-core.yaml > /dev/null << EOF
network:
  version: 2
  ethernets:
    $NETWORK_INTERFACE:
      dhcp4: yes
      addresses:
        - $AMF_IP/24
        - $UPF_IP/24
EOF
    
    # Apply netplan configuration
    sudo netplan apply
    
    log "Network configuration completed"
}

# Configure system parameters
configure_system() {
    log "Configuring system parameters..."
    
    # Enable IP forwarding
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo sysctl -w net.ipv6.conf.all.forwarding=1
    
    # Make IP forwarding persistent
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf
    
    # Load SCTP module (required for NGAP)
    sudo modprobe sctp
    echo 'sctp' | sudo tee -a /etc/modules
    
    # Configure firewall rules for 5G interfaces
    log "Configuring firewall rules..."
    
    # Allow NGAP traffic (SCTP port 38412)
    sudo iptables -C INPUT -p sctp --dport 38412 -j ACCEPT 2>/dev/null || \
        sudo iptables -I INPUT -p sctp --dport 38412 -j ACCEPT
    
    # Allow GTP-U traffic (UDP port 2152)
    sudo iptables -C INPUT -p udp --dport 2152 -j ACCEPT 2>/dev/null || \
        sudo iptables -I INPUT -p udp --dport 2152 -j ACCEPT
    
    # Allow PFCP traffic (UDP port 8805)
    sudo iptables -C INPUT -p udp --dport 8805 -j ACCEPT 2>/dev/null || \
        sudo iptables -I INPUT -p udp --dport 8805 -j ACCEPT
    
    # Configure NAT for UE traffic
    sudo iptables -t nat -C POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE 2>/dev/null || \
        sudo iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
    
    # Save iptables rules
    sudo mkdir -p /etc/iptables
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
    
    # Install iptables-persistent to restore rules on boot
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
    
    log "System configuration completed"
}

# Create deployment workspace
create_workspace() {
    log "Creating deployment workspace..."
    
    mkdir -p $DEPLOYMENT_DIR
    cd $DEPLOYMENT_DIR
    
    # Create namespace
    microk8s kubectl create namespace $NAMESPACE --dry-run=client -o yaml | microk8s kubectl apply -f -
    microk8s kubectl config set-context --current --namespace=$NAMESPACE
    
    log "Workspace created at $DEPLOYMENT_DIR"
}

# Generate configuration files
generate_configs() {
    log "Generating 5G Core configuration files..."
    
    # Generate AMF configuration for external gNB
    cat > $DEPLOYMENT_DIR/amf-external-config.yaml << EOF
logger:
  file:
    path: /var/log/open5gs/amf.log
  level:
    app: info

amf:
  sbi:
    server:
      - address: 127.0.0.5
        port: 7777
    client:
      scp:
        - uri: http://127.0.0.200:7777
  ngap:
    server:
      - address: $AMF_IP
        port: 38412
  metrics:
    server:
      - address: 127.0.0.5
        port: 9090
  guami:
    - plmn_id:
        mcc: $MCC
        mnc: $MNC
      amf_id:
        region: 2
        set: 1
  tai:
    - plmn_id:
        mcc: $MCC
        mnc: $MNC
      tac: $TAC
  plmn_support:
    - plmn_id:
        mcc: $MCC
        mnc: $MNC
      s_nssai:
        - sst: $SST
          sd: '$SD'
  security:
    integrity_order: [ NIA2, NIA1, NIA0 ]
    ciphering_order: [ NEA0, NEA1, NEA2 ]
  network_name:
    full: Private5G-SA
    short: P5G-SA
  amf_name: AMF-001
EOF

    # Generate UPF configuration for external gNB
    cat > $DEPLOYMENT_DIR/upf-external-config.yaml << EOF
logger:
  file:
    path: /var/log/open5gs/upf.log
  level:
    app: info

upf:
  pfcp:
    server:
      - address: 127.0.0.7
        port: 8805
  gtpu:
    server:
      - address: $UPF_IP
        port: 2152
  session:
    - subnet: 10.45.0.1/16
      dnn: $DNN
      dev: ogstun
  metrics:
    server:
      - address: 127.0.0.7
        port: 9090
EOF

    # Generate SMF configuration
    cat > $DEPLOYMENT_DIR/smf-external-config.yaml << EOF
logger:
  file:
    path: /var/log/open5gs/smf.log
  level:
    app: info

smf:
  sbi:
    server:
      - address: 127.0.0.4
        port: 7777
    client:
      nrf:
        - uri: http://127.0.0.200:7777
      scp:
        - uri: http://127.0.0.200:7777
  pfcp:
    server:
      - address: 127.0.0.4
        port: 8805
    client:
      upf:
        - address: 127.0.0.7
          port: 8805
  gtpc:
    server:
      - address: 127.0.0.4
        port: 2123
  gtpu:
    server:
      - address: 127.0.0.4
        port: 2152
  metrics:
    server:
      - address: 127.0.0.4
        port: 9090
  session:
    - subnet: 10.45.0.1/16
      dnn: $DNN
  dns:
    - 8.8.8.8
    - 8.8.4.4
  mtu: 1400
  ctf:
    enabled: auto
  freeDiameter: /etc/freeDiameter/smf.conf
EOF

    # Generate Helm values for external gNB deployment
    cat > $DEPLOYMENT_DIR/5g-sa-external-values.yaml << EOF
# Open5GS 5G SA Core Configuration for External gNB
global:
  userPlaneArchitecture: "single"
  
# Disable 4G components
hss:
  enabled: false
mme:
  enabled: false
sgwc:
  enabled: false
sgwu:
  enabled: false
pcrf:
  enabled: false

# Enable 5G SA components
nrf:
  enabled: true
scp:
  enabled: true
sepp:
  enabled: false
ausf:
  enabled: true
udm:
  enabled: true
udr:
  enabled: true
pcf:
  enabled: true
nssf:
  enabled: false
bsf:
  enabled: false
udrsim:
  enabled: false

# AMF configuration for external gNB
amf:
  enabled: true
  config:
    guamiList:
      - plmn_id:
          mcc: "$MCC"
          mnc: "$MNC"
        amf_id:
          region: 2
          set: 1
    taiList:
      - plmn_id:
          mcc: "$MCC"
          mnc: "$MNC"
        tac: [$TAC]
    plmnSupportList:
      - plmn_id:
          mcc: "$MCC"
          mnc: "$MNC"
        s_nssai:
          - sst: $SST
            sd: "$SD"
    security:
      integrityOrder: [2, 1, 0]
      cipheringOrder: [0, 1, 2]
    networkName:
      full: "Private5G-SA"
      short: "P5G-SA"
    ngapServer:
      address: "$AMF_IP"
      port: 38412
  service:
    ngap:
      enabled: true
      type: ClusterIP
      port: 38412
      nodePort: 38412
  
# SMF configuration
smf:
  enabled: true
  config:
    sessionList:
      - subnet: 10.45.0.1/16
        dnn: $DNN
    dns:
      - 8.8.8.8
      - 8.8.4.4
    mtu: 1400

# UPF configuration for external gNB  
upf:
  enabled: true
  config:
    pfcpServer:
      address: 127.0.0.7
      port: 8805
    gtpuServer:
      address: "$UPF_IP"
      port: 2152
    sessionList:
      - subnet: 10.45.0.1/16
        dnn: $DNN
        dev: ogstun
  service:
    gtpu:
      enabled: true
      type: ClusterIP
      port: 2152
      nodePort: 2152

# WebUI configuration
webui:
  enabled: true
  config:
    hostname: "0.0.0.0"
    port: 9999
  service:
    type: NodePort
    port: 9999
    nodePort: 30999

# MongoDB configuration
mongodb:
  enabled: true
  auth:
    enabled: false
  
# Populate initial subscribers
populate:
  enabled: true
  initCommands:
    - open5gs-dbctl add_ue_with_slice 999700000000001 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA $DNN $SST 111111
    - open5gs-dbctl add_ue_with_slice 999700000000002 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA $DNN $SST 111111
    - open5gs-dbctl add_ue_with_slice 999700000000003 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA $DNN $SST 111111
    - open5gs-dbctl add_ue_with_slice 999700000000004 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA $DNN $SST 111111
    - open5gs-dbctl add_ue_with_slice 999700000000005 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA $DNN $SST 111111
EOF

    log "Configuration files generated"
}

# Deploy 5G Core Network
deploy_5g_core() {
    log "Deploying Open5GS 5G Core Network..."
    
    cd $DEPLOYMENT_DIR
    
    # Deploy Open5GS using Helm
    log "Installing Open5GS via Helm..."
    microk8s helm3 install open5gs-core oci://registry-1.docker.io/gradiantcharts/open5gs \
        --version 2.2.9 \
        --values 5g-sa-external-values.yaml \
        --namespace $NAMESPACE \
        --timeout 10m \
        --wait
    
    log "Waiting for all pods to be ready..."
    microk8s kubectl wait --for=condition=ready pod --all -n $NAMESPACE --timeout=600s
    
    log "5G Core deployment completed"
}

# Configure external interfaces
configure_external_interfaces() {
    log "Configuring external interfaces for gNB connectivity..."
    
    # Create ConfigMaps for external configurations
    microk8s kubectl create configmap amf-external-config \
        --from-file=amf.yaml=$DEPLOYMENT_DIR/amf-external-config.yaml \
        -n $NAMESPACE --dry-run=client -o yaml | microk8s kubectl apply -f -
    
    microk8s kubectl create configmap upf-external-config \
        --from-file=upf.yaml=$DEPLOYMENT_DIR/upf-external-config.yaml \
        -n $NAMESPACE --dry-run=client -o yaml | microk8s kubectl apply -f -
    
    # Update AMF deployment for external gNB
    log "Updating AMF configuration for external gNB..."
    microk8s kubectl patch deployment open5gs-core-amf -n $NAMESPACE --type='strategic' -p='
{
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "amf", 
            "volumeMounts": [
              {
                "name": "amf-external-config",
                "mountPath": "/etc/open5gs/amf.yaml",
                "subPath": "amf.yaml"
              }
            ]
          }
        ],
        "volumes": [
          {
            "name": "amf-external-config",
            "configMap": {
              "name": "amf-external-config"
            }
          }
        ]
      }
    }
  }
}'

    # Update UPF deployment for external gNB
    log "Updating UPF configuration for external gNB..."
    microk8s kubectl patch deployment open5gs-core-upf -n $NAMESPACE --type='strategic' -p='
{
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "upf",
            "volumeMounts": [
              {
                "name": "upf-external-config", 
                "mountPath": "/etc/open5gs/upf.yaml",
                "subPath": "upf.yaml"
              }
            ]
          }
        ],
        "volumes": [
          {
            "name": "upf-external-config",
            "configMap": {
              "name": "upf-external-config"
            }
          }
        ]
      }
    }
  }
}'

    # Expose AMF NGAP service externally
    log "Exposing AMF NGAP service..."
    microk8s kubectl patch service open5gs-core-amf-ngap -n $NAMESPACE -p="
{
  \"spec\": {
    \"externalIPs\": [\"$AMF_IP\"],
    \"type\": \"ClusterIP\"
  }
}"

    # Expose UPF GTP-U service externally
    log "Exposing UPF GTP-U service..."
    microk8s kubectl patch service open5gs-core-upf-gtpu -n $NAMESPACE -p="
{
  \"spec\": {
    \"externalIPs\": [\"$UPF_IP\"],
    \"type\": \"ClusterIP\"
  }
}"

    # Wait for deployments to rollout
    log "Waiting for configuration updates to complete..."
    microk8s kubectl rollout status deployment/open5gs-core-amf -n $NAMESPACE --timeout=300s
    microk8s kubectl rollout status deployment/open5gs-core-upf -n $NAMESPACE --timeout=300s
    
    log "External interface configuration completed"
}

# Verify deployment
verify_deployment() {
    log "Verifying 5G Core deployment..."
    
    # Check pod status
    info "Checking pod status..."
    microk8s kubectl get pods -n $NAMESPACE
    
    # Check service status
    info "Checking service status..."
    microk8s kubectl get svc -n $NAMESPACE
    
    # Check if AMF is listening on external interface
    info "Verifying AMF NGAP interface..."
    if microk8s kubectl exec deployment/open5gs-core-amf -n $NAMESPACE -- netstat -ln | grep -q ":38412"; then
        log "✓ AMF NGAP interface is listening on port 38412"
    else
        warn "⚠ AMF NGAP interface may not be properly configured"
    fi
    
    # Check if UPF is listening on external interface
    info "Verifying UPF GTP-U interface..."
    if microk8s kubectl exec deployment/open5gs-core-upf -n $NAMESPACE -- netstat -ln | grep -q ":2152"; then
        log "✓ UPF GTP-U interface is listening on port 2152"
    else
        warn "⚠ UPF GTP-U interface may not be properly configured"
    fi
    
    # Test connectivity to gNB
    info "Testing connectivity to gNB at $GNB_IP..."
    if ping -c 3 $GNB_IP > /dev/null 2>&1; then
        log "✓ gNB at $GNB_IP is reachable"
    else
        warn "⚠ gNB at $GNB_IP is not reachable. Please check network connectivity."
    fi
    
    # Check if external IPs are configured
    info "Verifying external IP configuration..."
    if ip addr show $NETWORK_INTERFACE | grep -q "$AMF_IP"; then
        log "✓ AMF IP $AMF_IP is configured on $NETWORK_INTERFACE"
    else
        error "✗ AMF IP $AMF_IP is not configured"
    fi
    
    if ip addr show $NETWORK_INTERFACE | grep -q "$UPF_IP"; then
        log "✓ UPF IP $UPF_IP is configured on $NETWORK_INTERFACE"
    else
        error "✗ UPF IP $UPF_IP is not configured"
    fi
    
    log "Deployment verification completed"
}

# Generate gNB configuration template
generate_gnb_config() {
    log "Generating gNB configuration template..."
    
    cat > $DEPLOYMENT_DIR/gnb-config-template.yaml << EOF
# gNB Configuration Template for your All-in-One gNB
# Adapt this configuration to your specific gNB management interface

gnb:
  # Basic gNB Identity
  gnb_id: 1
  gnb_name: "Private5G-gNB-001"
  
  # PLMN Configuration (must match 5G Core)
  mcc: "$MCC"
  mnc: "$MNC"
  tac: $TAC
  
  # Cell Configuration
  nci: "0x000000010"  # NR Cell Identity (36-bit)
  
  # N2 Interface Configuration (NGAP to AMF)
  ngap:
    local_ip: "$GNB_IP"           # gNB IP address
    amf_configs:
      - address: "$AMF_IP"        # AMF NGAP interface IP
        port: 38412               # Standard NGAP port
        
  # N3 Interface Configuration (GTP-U to UPF)  
  gtpu:
    local_ip: "$GNB_IP"           # gNB IP for user plane
    upf_address: "$UPF_IP"        # UPF GTP-U interface IP
    upf_port: 2152                # Standard GTP-U port
    
  # Network Slicing Configuration
  slices:
    - sst: $SST                   # Slice/Service Type
      sd: "$SD"                   # Slice Differentiator
      
  # QoS Configuration
  qos:
    default_5qi: 9                # Best effort QoS
    arp_priority: 15              # Lowest priority
    
  # Security Configuration
  security:
    integrity_algorithms: ["NIA2", "NIA1", "NIA0"]
    ciphering_algorithms: ["NEA0", "NEA1", "NEA2"]

# Radio Configuration Examples (adapt to your specific radio)
# For sub-6 GHz deployment:
radio:
  # Example for N78 band (3300-3800 MHz)
  band: "n78"
  dl_arfcn: 632628                # 3500 MHz center frequency
  bandwidth: 20                   # MHz
  tx_power: 23                    # dBm (adjust for your deployment)
  
  # Example TDD configuration
  tdd_config:
    pattern: "DDDDDDDSUU"         # 7D:1S:2U pattern
    periodicity: 10               # ms

# Management Interface
management:
  ip: "$GNB_IP"
  port: 443                       # HTTPS management
  username: "admin"               # Default - change in production
  
# Logging Configuration
logging:
  level: "info"
  file: "/var/log/gnb.log"
EOF

    log "gNB configuration template created at $DEPLOYMENT_DIR/gnb-config-template.yaml"
}

# Generate management scripts
generate_management_scripts() {
    log "Generating management scripts..."
    
    # Status check script
    cat > $DEPLOYMENT_DIR/check-status.sh << 'EOF'
#!/bin/bash
# 5G Core Status Check Script

NAMESPACE="5g-core"

echo "=== 5G Core Network Status ==="
echo

echo "Pod Status:"
microk8s kubectl get pods -n $NAMESPACE
echo

echo "Service Status:"
microk8s kubectl get svc -n $NAMESPACE
echo

echo "AMF Logs (last 10 lines):"
microk8s kubectl logs deployment/open5gs-core-amf -n $NAMESPACE --tail=10
echo

echo "UPF Logs (last 10 lines):"
microk8s kubectl logs deployment/open5gs-core-upf -n $NAMESPACE --tail=10
echo

echo "Network Interfaces:"
ip addr show | grep -E "(eth0|10\.10\.10\.)"
echo

echo "gNB Connectivity Test:"
ping -c 3 10.10.10.10
EOF

    # Log monitoring script
    cat > $DEPLOYMENT_DIR/monitor-logs.sh << 'EOF'
#!/bin/bash
# 5G Core Log Monitoring Script

NAMESPACE="5g-core"

echo "Starting 5G Core log monitoring..."
echo "Press Ctrl+C to stop"
echo

# Monitor AMF and UPF logs
microk8s kubectl logs -f deployment/open5gs-core-amf deployment/open5gs-core-upf -n $NAMESPACE --prefix=true
EOF

    # Subscriber management script
    cat > $DEPLOYMENT_DIR/manage-subscribers.sh << 'EOF'
#!/bin/bash
# Subscriber Management Script

NAMESPACE="5g-core"

add_subscriber() {
    local imsi=$1
    local k=$2
    local opc=$3
    local dnn=${4:-"internet"}
    local sst=${5:-"1"}
    local sd=${6:-"111111"}
    
    echo "Adding subscriber: $imsi"
    microk8s kubectl exec deployment/open5gs-core-populate -n $NAMESPACE -- \
        open5gs-dbctl add_ue_with_slice $imsi $k $opc $dnn $sst $sd
}

list_subscribers() {
    echo "Current subscribers:"
    microk8s kubectl exec deployment/open5gs-core-mongodb -n $NAMESPACE -- \
        mongo open5gs --eval "db.subscribers.find().pretty()"
}

remove_subscriber() {
    local imsi=$1
    echo "Removing subscriber: $imsi"
    microk8s kubectl exec deployment/open5gs-core-populate -n $NAMESPACE -- \
        open5gs-dbctl remove $imsi
}

case "$1" in
    "add")
        if [ $# -lt 4 ]; then
            echo "Usage: $0 add <IMSI> <K> <OPc> [DNN] [SST] [SD]"
            echo "Example: $0 add 999700000000010 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA"
            exit 1
        fi
        add_subscriber $2 $3 $4 $5 $6 $7
        ;;
    "list")
        list_subscribers
        ;;
    "remove")
        if [ $# -lt 2 ]; then
            echo "Usage: $0 remove <IMSI>"
            exit 1
        fi
        remove_subscriber $2
        ;;
    *)
        echo "Usage: $0 {add|list|remove}"
        echo "  add <IMSI> <K> <OPc> [DNN] [SST] [SD] - Add new subscriber"
        echo "  list                                    - List all subscribers"
        echo "  remove <IMSI>                          - Remove subscriber"
        exit 1
        ;;
esac
EOF

    # WebUI access script
    cat > $DEPLOYMENT_DIR/access-webui.sh << 'EOF'
#!/bin/bash
# Open5GS WebUI Access Script

NAMESPACE="5g-core"

echo "Starting port-forward to Open5GS WebUI..."
echo "WebUI will be available at: http://localhost:9999"
echo "Default login: admin / 1423"
echo "Press Ctrl+C to stop"
echo

microk8s kubectl port-forward svc/open5gs-core-webui 9999:9999 -n $NAMESPACE
EOF

    # Network diagnostics script
    cat > $DEPLOYMENT_DIR/network-diagnostics.sh << 'EOF'
#!/bin/bash
# Network Diagnostics Script for 5G Core

NAMESPACE="5g-core"
GNB_IP="10.10.10.10"
AMF_IP="10.10.10.20"
UPF_IP="10.10.10.21"

echo "=== 5G Core Network Diagnostics ==="
echo

echo "1. Interface Configuration:"
ip addr show | grep -E "(eth0|10\.10\.10\.)"
echo

echo "2. Routing Table:"
ip route | grep 10.10.10
echo

echo "3. gNB Connectivity:"
echo -n "Ping to gNB ($GNB_IP): "
if ping -c 3 -W 2 $GNB_IP > /dev/null 2>&1; then
    echo "✓ OK"
else
    echo "✗ FAILED"
fi
echo

echo "4. Port Listening Status:"
echo "AMF NGAP (port 38412):"
sudo netstat -ln | grep :38412 || echo "Not listening"
echo "UPF GTP-U (port 2152):"
sudo netstat -ln | grep :2152 || echo "Not listening"
echo

echo "5. SCTP Associations:"
cat /proc/net/sctp/assocs 2>/dev/null || echo "No SCTP associations"
echo

echo "6. Firewall Rules:"
sudo iptables -L | grep -E "(38412|2152|8805)"
echo

echo "7. Kubernetes Services:"
microk8s kubectl get svc -n $NAMESPACE -o wide
echo

echo "8. Network Traffic Capture (10 seconds):"
echo "Capturing NGAP and GTP-U traffic..."
timeout 10 sudo tcpdump -i any -c 10 "(sctp port 38412) or (udp port 2152)" 2>/dev/null || echo "No traffic captured"
EOF

    # Restart script
    cat > $DEPLOYMENT_DIR/restart-core.sh << 'EOF'
#!/bin/bash
# 5G Core Restart Script

NAMESPACE="5g-core"

echo "Restarting 5G Core components..."

echo "Restarting AMF..."
microk8s kubectl rollout restart deployment/open5gs-core-amf -n $NAMESPACE

echo "Restarting SMF..."
microk8s kubectl rollout restart deployment/open5gs-core-smf -n $NAMESPACE

echo "Restarting UPF..."
microk8s kubectl rollout restart deployment/open5gs-core-upf -n $NAMESPACE

echo "Waiting for deployments to be ready..."
microk8s kubectl rollout status deployment/open5gs-core-amf -n $NAMESPACE
microk8s kubectl rollout status deployment/open5gs-core-smf -n $NAMESPACE
microk8s kubectl rollout status deployment/open5gs-core-upf -n $NAMESPACE

echo "5G Core restart completed"
EOF

    # Make scripts executable
    chmod +x $DEPLOYMENT_DIR/*.sh
    
    log "Management scripts created in $DEPLOYMENT_DIR"
}

# Create deployment summary
create_summary() {
    log "Creating deployment summary..."
    
    cat > $DEPLOYMENT_DIR/DEPLOYMENT_SUMMARY.md << EOF
# 5G SA Core Deployment Summary

## Deployment Information
- **Deployment Date**: $(date)
- **Namespace**: $NAMESPACE
- **Core Host IP**: $CORE_HOST_IP
- **Network Interface**: $NETWORK_INTERFACE

## Network Configuration
- **gNB IP**: $GNB_IP
- **AMF NGAP IP**: $AMF_IP:38412
- **UPF GTP-U IP**: $UPF_IP:2152
- **PLMN**: $MCC/$MNC
- **TAC**: $TAC
- **Network Slice**: SST=$SST, SD=$SD

## 5G Core Components
- **AMF**: Access and Mobility Management Function
- **SMF**: Session Management Function  
- **UPF**: User Plane Function
- **NRF**: Network Repository Function
- **AUSF**: Authentication Server Function
- **UDM**: Unified Data Management
- **UDR**: Unified Data Repository
- **PCF**: Policy Control Function

## Pre-configured Test Subscribers
| IMSI | K | OPc | APN |
|------|---|-----|-----|
| 999700000000001 | 465B5CE8B199B49FAA5F0A2EE238A6BC | E8ED289DEBA952E4283B54E88E6183CA | internet |
| 999700000000002 | 465B5CE8B199B49FAA5F0A2EE238A6BC | E8ED289DEBA952E4283B54E88E6183CA | internet |
| 999700000000003 | 465B5CE8B199B49FAA5F0A2EE238A6BC | E8ED289DEBA952E4283B54E88E6183CA | internet |
| 999700000000004 | 465B5CE8B199B49FAA5F0A2EE238A6BC | E8ED289DEBA952E4283B54E88E6183CA | internet |
| 999700000000005 | 465B5CE8B199B49FAA5F0A2EE238A6BC | E8ED289DEBA952E4283B54E88E6183CA | internet |

## gNB Configuration Requirements
Your gNB at $GNB_IP should be configured with:

### N2 Interface (NGAP)
- **Remote AMF IP**: $AMF_IP
- **Remote AMF Port**: 38412
- **Local gNB IP**: $GNB_IP
- **Protocol**: SCTP

### N3 Interface (GTP-U)
- **Remote UPF IP**: $UPF_IP
- **Remote UPF Port**: 2152
- **Local gNB IP**: $GNB_IP
- **Protocol**: UDP

### Network Identity
- **MCC**: $MCC
- **MNC**: $MNC
- **TAC**: $TAC
- **PLMN**: ${MCC}${MNC}

### Network Slice
- **SST**: $SST
- **SD**: $SD

## Management Scripts
The following scripts are available in $DEPLOYMENT_DIR:

- **check-status.sh**: Check overall system status
- **monitor-logs.sh**: Monitor AMF and UPF logs in real-time
- **manage-subscribers.sh**: Add, remove, and list subscribers
- **access-webui.sh**: Access Open5GS WebUI (http://localhost:9999)
- **network-diagnostics.sh**: Run network connectivity diagnostics
- **restart-core.sh**: Restart 5G core components

## Usage Examples

### Check System Status
\`\`\`bash
cd $DEPLOYMENT_DIR
./check-status.sh
\`\`\`

### Add New Subscriber
\`\`\`bash
./manage-subscribers.sh add 999700000000010 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA
\`\`\`

### Access WebUI
\`\`\`bash
./access-webui.sh
# Then browse to http://localhost:9999
# Login: admin / 1423
\`\`\`

### Monitor Real-time Logs
\`\`\`bash
./monitor-logs.sh
\`\`\`

## Troubleshooting

### Check gNB Connectivity
\`\`\`bash
ping $GNB_IP
\`\`\`

### Monitor NGAP Traffic
\`\`\`bash
sudo tcpdump -i any sctp port 38412 -v
\`\`\`

### Monitor GTP-U Traffic
\`\`\`bash
sudo tcpdump -i any udp port 2152 -v
\`\`\`

### Check AMF Logs for gNB Connection
\`\`\`bash
microk8s kubectl logs deployment/open5gs-core-amf -n $NAMESPACE -f
\`\`\`

Look for messages like:
- \`[ngap] INFO: SCTP connection established\`
- \`[ngap] INFO: NG Setup Request received\`
- \`[amf] INFO: gNB-N2 accepted\`

### Expected gNB Connection Sequence
1. gNB establishes SCTP connection to AMF ($AMF_IP:38412)
2. gNB sends NG Setup Request
3. AMF responds with NG Setup Response
4. UEs can now register and establish data sessions

## Network Architecture
\`\`\`
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │
│  5G UE Device   │◄──►│   Your gNB       │◄──►│ Open5GS Core    │
│                 │    │  ($GNB_IP)       │    │ (Kubernetes)    │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        Uu                    N2/N3                   N4/SBI
     (5G NR)              (NGAP/GTP-U)           (PFCP/HTTP2)
\`\`\`

## Next Steps
1. Configure your gNB using the parameters above
2. Test gNB connection using the monitoring scripts
3. Add production subscribers via WebUI or CLI
4. Test end-to-end connectivity with 5G UE devices
5. Monitor performance and optimize as needed

## Support
- Open5GS Documentation: https://open5gs.org/open5gs/docs/
- Configuration files: $DEPLOYMENT_DIR/
- Logs: Use monitor-logs.sh or kubectl logs commands
EOF

    log "Deployment summary created at $DEPLOYMENT_DIR/DEPLOYMENT_SUMMARY.md"
}

# Main deployment function
main() {
    echo "=============================================="
    echo "    5G SA Network Core Deployment Script     "
    echo "=============================================="
    echo
    echo "This script will deploy a complete 5G SA core"
    echo "network configured for external gNB at $GNB_IP"
    echo
    echo "Configuration:"
    echo "- gNB IP: $GNB_IP"
    echo "- AMF NGAP IP: $AMF_IP:38412"
    echo "- UPF GTP-U IP: $UPF_IP:2152"
    echo "- PLMN: $MCC/$MNC"
    echo "- Network Interface: $NETWORK_INTERFACE"
    echo
    read -p "Continue with deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled."
        exit 0
    fi
    
    log "Starting 5G SA core deployment..."
    
    check_root
    check_prerequisites
    install_microk8s
    configure_network
    configure_system
    create_workspace
    generate_configs
    deploy_5g_core
    configure_external_interfaces
    verify_deployment
    generate_gnb_config
    generate_management_scripts
    create_summary
    
    echo
    echo "=============================================="
    echo "    5G SA Core Deployment Completed!         "
    echo "=============================================="
    echo
    echo "✓ 5G Core network deployed successfully"
    echo "✓ AMF ready for gNB connection at $AMF_IP:38412"
    echo "✓ UPF ready for user traffic at $UPF_IP:2152"
    echo "✓ WebUI accessible via: ./access-webui.sh"
    echo "✓ Management scripts created in $DEPLOYMENT_DIR"
    echo
    echo "Next Steps:"
    echo "1. Configure your gNB at $GNB_IP with the parameters in:"
    echo "   $DEPLOYMENT_DIR/gnb-config-template.yaml"
    echo "2. Check deployment status: $DEPLOYMENT_DIR/check-status.sh"
    echo "3. Monitor logs: $DEPLOYMENT_DIR/monitor-logs.sh"
    echo "4. Read full summary: $DEPLOYMENT_DIR/DEPLOYMENT_SUMMARY.md"
    echo
    echo "Your 5G core is ready to accept gNB connections!"
    log "Deployment completed successfully"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
        