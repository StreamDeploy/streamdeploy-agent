#!/bin/bash

# StreamDeploy Agent Secret Provisioning Script
# This script fetches secrets from GCP Secret Manager and deploys them securely to devices

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-stream-deploy-888888}"
SECRETS_DIR="${SECRETS_DIR:-/etc/streamdeploy/secrets}"
ENVIRONMENT="${ENVIRONMENT:-prod}"
AGENT_USER="${AGENT_USER:-streamdeploy}"
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for proper file permissions"
        exit 1
    fi
    
    # Check if gcloud is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        log_error "No active gcloud authentication found. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Check project access
    if ! gcloud projects describe "$PROJECT_ID" &> /dev/null; then
        log_error "Cannot access project $PROJECT_ID. Check permissions."
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Function to create secrets directory with proper permissions
setup_secrets_directory() {
    log_info "Setting up secrets directory: $SECRETS_DIR"
    
    # Create directory if it doesn't exist
    mkdir -p "$SECRETS_DIR"
    
    # Set proper ownership and permissions
    chown root:root "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"
    
    log_debug "Secrets directory created with permissions 700"
}

# Function to fetch and deploy a secret
deploy_secret() {
    local secret_name="$1"
    local file_name="$2"
    local file_path="$SECRETS_DIR/$file_name"
    
    log_info "Deploying secret: $secret_name -> $file_name"
    
    # Fetch secret from Secret Manager
    if ! gcloud secrets versions access latest --secret="$secret_name" --project="$PROJECT_ID" > "$file_path.tmp" 2>/dev/null; then
        log_warn "Failed to fetch secret '$secret_name', skipping..."
        rm -f "$file_path.tmp"
        return 1
    fi
    
    # Validate secret is not empty
    if [[ ! -s "$file_path.tmp" ]]; then
        log_warn "Secret '$secret_name' is empty, skipping..."
        rm -f "$file_path.tmp"
        return 1
    fi
    
    # Move to final location atomically
    mv "$file_path.tmp" "$file_path"
    
    # Set proper permissions (600 - owner read/write only)
    chown root:root "$file_path"
    chmod 600 "$file_path"
    
    log_debug "Secret '$secret_name' deployed successfully with permissions 600"
    return 0
}

# Function to validate deployed secrets
validate_secrets() {
    log_info "Validating deployed secrets..."
    
    local validation_failed=false
    
    for file in "$SECRETS_DIR"/*; do
        if [[ -f "$file" ]]; then
            local filename=$(basename "$file")
            
            # Check file permissions
            local perms=$(stat -c "%a" "$file")
            if [[ "$perms" != "600" ]]; then
                log_error "Invalid permissions on $filename: $perms (should be 600)"
                validation_failed=true
            fi
            
            # Check file ownership
            local owner=$(stat -c "%U:%G" "$file")
            if [[ "$owner" != "root:root" ]]; then
                log_error "Invalid ownership on $filename: $owner (should be root:root)"
                validation_failed=true
            fi
            
            # Check file is not empty
            if [[ ! -s "$file" ]]; then
                log_error "Secret file $filename is empty"
                validation_failed=true
            fi
            
            log_debug "Validated secret file: $filename"
        fi
    done
    
    if [[ "$validation_failed" == "true" ]]; then
        log_error "Secret validation failed"
        exit 1
    fi
    
    log_info "All secrets validated successfully"
}

# Function to create agent user if it doesn't exist
create_agent_user() {
    if ! id "$AGENT_USER" &>/dev/null; then
        log_info "Creating agent user: $AGENT_USER"
        useradd --system --no-create-home --shell /bin/false "$AGENT_USER"
    else
        log_debug "Agent user $AGENT_USER already exists"
    fi
}

# Function to set up systemd service permissions
setup_service_permissions() {
    log_info "Setting up service permissions..."
    
    # Allow agent user to read secrets directory
    setfacl -m u:$AGENT_USER:rx "$SECRETS_DIR" 2>/dev/null || {
        log_warn "setfacl not available, using group permissions instead"
        chgrp "$AGENT_USER" "$SECRETS_DIR"
        chmod 750 "$SECRETS_DIR"
    }
    
    log_debug "Service permissions configured"
}

# Main deployment function
deploy_all_secrets() {
    log_info "Starting secret deployment for environment: $ENVIRONMENT"
    
    # Define secrets to deploy
    declare -A secrets=(
        ["streamdeploy-ssh-bastion-host"]="ssh_bastion_host"
        ["streamdeploy-ssh-bastion-user"]="ssh_bastion_user"
        ["streamdeploy-bootstrap-token"]="bootstrap_token"
        ["streamdeploy-enroll-base-url"]="enroll_base_url"
        ["streamdeploy-device-base-url"]="device_base_url"
    )
    
    local deployed_count=0
    local failed_count=0
    
    # Deploy each secret
    for secret_name in "${!secrets[@]}"; do
        local file_name="${secrets[$secret_name]}"
        
        if deploy_secret "$secret_name" "$file_name"; then
            ((deployed_count++))
        else
            ((failed_count++))
        fi
    done
    
    log_info "Deployment complete: $deployed_count deployed, $failed_count failed"
    
    if [[ $failed_count -gt 0 ]]; then
        log_warn "Some secrets failed to deploy. Agent will use config file fallbacks."
    fi
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy StreamDeploy agent secrets from GCP Secret Manager

OPTIONS:
    -p, --project PROJECT_ID    GCP project ID (default: stream-deploy-888888)
    -d, --secrets-dir DIR       Secrets directory (default: /etc/streamdeploy/secrets)
    -e, --environment ENV       Environment (dev/staging/prod, default: prod)
    -u, --user USER            Agent user (default: streamdeploy)
    -v, --verbose              Enable verbose logging
    -h, --help                 Show this help message

EXAMPLES:
    # Deploy production secrets
    sudo $0

    # Deploy staging secrets with verbose output
    sudo $0 --environment staging --verbose

    # Deploy to custom directory
    sudo $0 --secrets-dir /opt/streamdeploy/secrets

ENVIRONMENT VARIABLES:
    PROJECT_ID                 GCP project ID
    SECRETS_DIR               Target directory for secrets
    ENVIRONMENT               Deployment environment
    AGENT_USER                System user for agent service
    VERBOSE                   Enable verbose output (true/false)

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--project)
                PROJECT_ID="$2"
                shift 2
                ;;
            -d|--secrets-dir)
                SECRETS_DIR="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -u|--user)
                AGENT_USER="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Cleanup function
cleanup() {
    log_debug "Cleaning up temporary files..."
    rm -f "$SECRETS_DIR"/*.tmp 2>/dev/null || true
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Main execution
main() {
    log_info "StreamDeploy Agent Secret Provisioning"
    log_info "Project: $PROJECT_ID, Environment: $ENVIRONMENT"
    
    parse_arguments "$@"
    check_prerequisites
    setup_secrets_directory
    create_agent_user
    deploy_all_secrets
    validate_secrets
    setup_service_permissions
    
    log_info "Secret provisioning completed successfully!"
    log_info "Secrets deployed to: $SECRETS_DIR"
    log_info "Agent can now use secure file-based secrets with config fallbacks"
}

# Run main function with all arguments
main "$@"
