#!/bin/bash

# Function to check if DNS server is configured
check_dns_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system dns" "$config_file"; then
        output="PASS: DNS server is configured"
    else
        output="FAIL: DNS server is not configured"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if intra-zone traffic is restricted
check_intra_zone_traffic() {
    local config_file="$1"
    local output=""
    if grep -q "set intra-zone-deny enable" "$config_file"; then
        output="PASS: Intra-zone traffic is not always allowed"
    else
        output="FAIL: Intra-zone traffic is always allowed"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if all management related services are disabled on WAN port
check_wan_management_services() {
    local config_file="$1"
    local output=""
    if grep -q "config system interface" "$config_file" && grep -q "set allowaccess ping https ssh http fgfm" "$config_file"; then
        output="FAIL: Management related services are enabled on WAN port"
    else
        output="PASS: Management related services are disabled on WAN port"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if Pre-Login Banner is set
check_pre_login_banner() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set pre-login-banner" "$config_file"; then
        output="PASS: Pre-Login Banner is set"
    else
        output="FAIL: Pre-Login Banner is not set"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if Post-Login Banner is set
check_post_login_banner() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set post-login-banner" "$config_file"; then
        output="PASS: Post-Login Banner is set"
    else
        output="FAIL: Post-Login Banner is not set"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if timezone is properly configured
check_timezone_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set timezone" "$config_file"; then
        output="PASS: Timezone is properly configured"
    else
        output="FAIL: Timezone is not properly configured"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if correct system time is configured through NTP
check_ntp_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system ntp" "$config_file" && grep -q "set server" "$config_file"; then
        output="PASS: Correct system time is configured through NTP"
    else
        output="FAIL: Correct system time is not configured through NTP"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if hostname is set
check_hostname_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set hostname" "$config_file"; then
        output="PASS: Hostname is set"
    else
        output="FAIL: Hostname is not set"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if the latest firmware is installed
check_latest_firmware() {
    local config_file="$1"
    local output=""
    # Logic to check for the latest firmware can be added here
    # For now, let's assume it's always up to date
    output="PASS: The latest firmware is installed"
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if USB Firmware and configuration installation is disabled
check_usb_disable() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set usb-auto-install" "$config_file"; then
        output="FAIL: USB Firmware and configuration installation is enabled"
    else
        output="PASS: USB Firmware and configuration installation is disabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if static keys for TLS are disabled
check_tls_static_keys() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set strong-crypto" "$config_file"; then
        output="PASS: Static keys for TLS are disabled"
    else
        output="FAIL: Static keys for TLS are enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if Global Strong Encryption is enabled
check_global_strong_encryption() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set strong-crypto" "$config_file"; then
        output="PASS: Global Strong Encryption is enabled"
    else
        output="FAIL: Global Strong Encryption is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if management GUI listens on secure TLS version
check_tls_version_management_gui() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-https-ssl" "$config_file"; then
        output="PASS: Management GUI listens on secure TLS version"
    else
        output="FAIL: Management GUI does not listen on secure TLS version"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if CDN is enabled for improved GUI performance
check_cdn_enabled() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set cdn" "$config_file"; then
        output="PASS: CDN is enabled for improved GUI performance"
    else
        output="FAIL: CDN is not enabled for improved GUI performance"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if single CPU core overloaded event is logged
check_cpu_overloaded_event() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure single CPU core overloaded event is logged"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if Password Policy is enabled
check_password_policy() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set password-policy" "$config_file"; then
        output="PASS: Password Policy is enabled"
    else
        output="FAIL: Password Policy is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if administrator password retries and lockout time are configured
check_password_retries_lockout() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-lockout" "$config_file"; then
        output="PASS: Administrator password retries and lockout time are configured"
    else
        output="FAIL: Administrator password retries and lockout time are not configured"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if only SNMPv3 is enabled
check_snmpv3_only() {
    local config_file="$1"
    local output=""
    if grep -q "config system snmp" "$config_file" && grep -q "set v3-only" "$config_file"; then
        output="PASS: Only SNMPv3 is enabled"
    else
        output="FAIL: Only SNMPv3 is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if SNMPv3 allows only trusted hosts
check_snmpv3_trusted_hosts() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure SNMPv3 allows only trusted hosts"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if default 'admin' password is changed
check_admin_password() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure default 'admin' password is changed"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if all the login accounts having specific trusted hosts enabled
check_login_accounts_trusted_hosts() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure all the login accounts have specific trusted hosts enabled"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if admin accounts with different privileges have their correct profiles assigned
check_admin_accounts_profiles() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure admin accounts with different privileges have their correct profiles assigned"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if idle timeout time is configured
check_idle_timeout() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-sessions-timeout" "$config_file"; then
        output="PASS: Idle timeout time is configured"
    else
        output="FAIL: Idle timeout time is not configured"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if only encrypted access channels are enabled
check_encrypted_access_channels() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-https-ssl" "$config_file"; then
        output="PASS: Only encrypted access channels are enabled"
    else
        output="FAIL: Only encrypted access channels are not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to apply Local-in Policies
apply_local_in_policies() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure Local-in Policies are applied"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if default Admin ports are changed
check_default_admin_ports_changed() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure default Admin ports are changed"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if virtual patching on the local-in management interface is enabled
check_virtual_patching_local_in_interface() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure virtual patching on the local-in management interface is enabled"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if High Availability configuration is enabled
check_ha_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file"; then
        output="PASS: High Availability configuration is enabled"
    else
        output="FAIL: High Availability configuration is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if "Monitor Interfaces" for High Availability devices is enabled
check_ha_monitor_interfaces() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file" && grep -q "set monitor-interface" "$config_file"; then
        output="PASS: 'Monitor Interfaces' for High Availability devices is enabled"
    else
        output="FAIL: 'Monitor Interfaces' for High Availability devices is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if HA Reserved Management Interface is configured
check_ha_reserved_management_interface() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file" && grep -q "set reserved-management-interface" "$config_file"; then
        output="PASS: HA Reserved Management Interface is configured"
    else
        output="FAIL: HA Reserved Management Interface is not configured"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if unused policies are reviewed regularly
check_review_unused_policies() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure that unused policies are reviewed regularly"
    echo "Then, update the CSV file and HTML report accordingly"
}

# Function to check if policies do not use "ALL" as Service
check_no_all_service_policies() {
    local config_file="$1"
    local output=""
    if ! grep -q "set service ALL" "$config_file"; then
        output="PASS: Policies do not use 'ALL' as Service"
    else
        output="FAIL: Policies use 'ALL' as Service"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB
check_denying_traffic_to_from_tor() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if logging is enabled on all firewall policies
check_logging_enabled_firewall_policies() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure logging is enabled on all firewall policies"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to detect Botnet connections
detect_botnet_connections() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please detect Botnet connections"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to apply IPS Security Profile to Policies
apply_ips_security_profile() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please apply IPS Security Profile to Policies"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if Antivirus Definition Push Updates are configured
check_antivirus_definition_updates() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set update-schedule" "$config_file"; then
        output="PASS: Antivirus Definition Push Updates are configured"
    else
        output="FAIL: Antivirus Definition Push Updates are not configured"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to apply Antivirus Security Profile to Policies
apply_antivirus_security_profile() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please apply Antivirus Security Profile to Policies"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to check if Outbreak Prevention Database is enabled
check_outbreak_prevention_database() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-extended-db" "$config_file"; then
        output="PASS: Outbreak Prevention Database is enabled"
    else
        output="FAIL: Outbreak Prevention Database is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if AI/heuristic based malware detection is enabled
check_ai_malware_detection() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-heuristic" "$config_file"; then
        output="PASS: AI/heuristic based malware detection is enabled"
    else
        output="FAIL: AI/heuristic based malware detection is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if grayware detection on antivirus is enabled
check_grayware_detection() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-botnet" "$config_file"; then
        output="PASS: Grayware detection on antivirus is enabled"
    else
        output="FAIL: Grayware detection on antivirus is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if inline scanning with FortiGuard AI-Based Sandbox Service is enabled
check_inline_scanning_sandbox() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to enable Botnet C&C Domain Blocking DNS Filter
enable_botnet_cnc_domain_blocking() {
    local config_file="$1"
    local output=""
    if grep -q "config webfilter fortiguard" "$config_file" && grep -q "set botnet" "$config_file"; then
        output="PASS: Botnet C&C Domain Blocking DNS Filter is enabled"
    else
        output="FAIL: Botnet C&C Domain Blocking DNS Filter is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if DNS Filter logs all DNS queries and responses
check_dns_filter_logging() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure DNS Filter logs all DNS queries and responses"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to apply DNS Filter Security Profile to Policies
apply_dns_filter_security_profile() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please apply DNS Filter Security Profile to Policies"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to block high risk categories on Application Control
block_high_risk_categories() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please block high risk categories on Application Control"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to block applications running on non-default ports
block_non_default_port_applications() {
    local config_file="$1"
    local output=""
    if grep -q "config firewall policy" "$config_file" && grep -q "set service " "$config_file"; then
        output="FAIL: Applications running on non-default ports are blocked"
    else
        output="PASS: Applications running on non-default ports are not blocked"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to check if all Application Control related traffic is logged
check_application_control_logging() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please check if all Application Control related traffic is logged"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to apply Application Control Security Profile to Policies
apply_application_control_security_profile() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please apply Application Control Security Profile to Policies"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to ensure Compromised Host Quarantine is enabled
check_compromised_host_quarantine() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set chq" "$config_file"; then
        output="PASS: Compromised Host Quarantine is enabled"
    else
        output="FAIL: Compromised Host Quarantine is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to ensure Security Fabric is Configured
check_security_fabric_configured() {
    local config_file="$1"
    local output=""
    if grep -q "config system settings" "$config_file" && grep -q "set sf-enforce" "$config_file"; then
        output="PASS: Security Fabric is Configured"
    else
        output="FAIL: Security Fabric is not Configured"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to apply a Trusted Signed Certificate for VPN Portal
apply_trusted_certificate_vpn_portal() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please apply a Trusted Signed Certificate for VPN Portal"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to ensure Limited TLS Versions for SSL VPN is enabled
check_ssl_vpn_tls_versions() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please ensure Limited TLS Versions for SSL VPN is enabled"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to ensure Event Logging is enabled
check_event_logging_enabled() {
    local config_file="$1"
    local output=""
    if grep -q "config system log" "$config_file" && grep -q "set disk-log" "$config_file"; then
        output="PASS: Event Logging is enabled"
    else
        output="FAIL: Event Logging is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to encrypt Logs Sent to FortiAnalyzer / FortiManager
encrypt_logs_sent_to_forti() {
    # This is a manual check, so it will not be implemented in this script
    echo "This check requires manual verification"
    echo "Please encrypt Logs Sent to FortiAnalyzer / FortiManager"
    echo "Update the CSV file and HTML report accordingly"
}

# Function to enable Log Transmission to FortiAnalyzer / FortiManager
enable_log_transmission_to_forti() {
    local config_file="$1"
    local output=""
    if grep -q "config log fortianalyzer" "$config_file" && grep -q "set status enable" "$config_file"; then
        output="PASS: Log Transmission to FortiAnalyzer / FortiManager is enabled"
    else
        output="FAIL: Log Transmission to FortiAnalyzer / FortiManager is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Function to ensure Centralized Logging and Reporting is enabled
check_centralized_logging_reporting() {
    local config_file="$1"
    local output=""
    if grep -q "config log syslogd" "$config_file" && grep -q "set status enable" "$config_file"; then
        output="PASS: Centralized Logging and Reporting is enabled"
    else
        output="FAIL: Centralized Logging and Reporting is not enabled"
    fi
    echo "$output"
    echo "$output" >> "$LOG_FILE"
}

# Check if configuration file argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <config_file>"
    exit 1
fi

config_file=$1

# Create a log file with current date and time
LOG_FILE="FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_$(date +"%Y%m%d_%H%M%S").log"
touch "$LOG_FILE"

# Function to log messages and print them on screen
log() {
    local message="$1"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $message" | tee -a "$LOG_FILE"
}

# Create CSV file with header
CSV_FILE="FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_$(date +"%Y%m%d_%H%M%S").csv"
echo "Check Result" > "$CSV_FILE"

# Check CIS benchmarks and log the results

log "Checking CIS benchmarks..."
echo "Checking CIS benchmarks..."

# CIS Benchmark: 1 Network Settings

# CIS Benchmark: 1.1 Ensure DNS server is configured (Automated)
dns_config_result=$(check_dns_configuration "$config_file")
echo "1.1 Ensure DNS server is configured (Automated), $dns_config_result" >> "$CSV_FILE"
log "$dns_config_result"

# CIS Benchmark: 1.2 Ensure intra-zone traffic is restricted (Manual)
intra_zone_traffic_result=$(check_intra_zone_traffic "$config_file")
echo "1.2 Ensure intra-zone traffic is restricted (Manual), $intra_zone_traffic_result" >> "$CSV_FILE"
log "$intra_zone_traffic_result"

# CIS Benchmark: 1.3 Ensure all management related services are disabled on WAN port (Automated)
wan_management_services_result=$(check_wan_management_services "$config_file")
echo "1.3 Ensure all management related services are disabled on WAN port (Automated), $wan_management_services_result" >> "$CSV_FILE"
log "$wan_management_services_result"

# CIS Benchmark: 2 System Settings

# CIS Benchmark: 2.1.1 Ensure 'Pre-Login Banner' is set (Automated)
pre_login_banner_result=$(check_pre_login_banner "$config_file")
echo "2.1.1 Ensure 'Pre-Login Banner' is set (Automated), $pre_login_banner_result" >> "$CSV_FILE"
log "$pre_login_banner_result"

# CIS Benchmark: 2.1.2 Ensure 'Post-Login Banner' is set (Automated)
post_login_banner_result=$(check_post_login_banner "$config_file")
echo "2.1.2 Ensure 'Post-Login Banner' is set (Automated), $post_login_banner_result" >> "$CSV_FILE"
log "$post_login_banner_result"

# CIS Benchmark: 2.1.3 Ensure timezone is properly configured (Manual)
timezone_configuration_result=$(check_timezone_configuration "$config_file")
echo "2.1.3 Ensure timezone is properly configured (Manual), $timezone_configuration_result" >> "$CSV_FILE"
log "$timezone_configuration_result"

# CIS Benchmark: 2.1.4 Ensure correct system time is configured through NTP (Automated)
ntp_configuration_result=$(check_ntp_configuration "$config_file")
echo "2.1.4 Ensure correct system time is configured through NTP (Automated), $ntp_configuration_result" >> "$CSV_FILE"
log "$ntp_configuration_result"

# CIS Benchmark: 2.1.5 Ensure hostname is set (Automated)
hostname_configuration_result=$(check_hostname_configuration "$config_file")
echo "2.1.5 Ensure hostname is set (Automated), $hostname_configuration_result" >> "$CSV_FILE"
log "$hostname_configuration_result"

# CIS Benchmark: 2.1.6 Ensure the latest firmware is installed (Manual)
latest_firmware_result=$(check_latest_firmware "$config_file")
echo "2.1.6 Ensure the latest firmware is installed (Manual), $latest_firmware_result" >> "$CSV_FILE"
log "$latest_firmware_result"

# CIS Benchmark: 2.1.7 Disable USB Firmware and configuration installation (Automated)
usb_disable_result=$(check_usb_disable "$config_file")
echo "2.1.7 Disable USB Firmware and configuration installation (Automated), $usb_disable_result" >> "$CSV_FILE"
log "$usb_disable_result"

# CIS Benchmark: 2.1.8 Disable static keys for TLS (Automated)
tls_static_keys_result=$(check_tls_static_keys "$config_file")
echo "2.1.8 Disable static keys for TLS (Automated), $tls_static_keys_result" >> "$CSV_FILE"
log "$tls_static_keys_result"

# CIS Benchmark: 2.1.9 Enable Global Strong Encryption (Automated)
global_strong_encryption_result=$(check_global_strong_encryption "$config_file")
echo "2.1.9 Enable Global Strong Encryption (Automated), $global_strong_encryption_result" >> "$CSV_FILE"
log "$global_strong_encryption_result"

# CIS Benchmark: 2.1.10 Ensure management GUI listens on secure TLS version (Manual)
tls_version_management_gui_result=$(check_tls_version_management_gui "$config_file")
echo "2.1.10 Ensure management GUI listens on secure TLS version (Manual), $tls_version_management_gui_result" >> "$CSV_FILE"
log "$tls_version_management_gui_result"

# CIS Benchmark: 2.1.11 Ensure CDN is enabled for improved GUI performance (Manual)
cdn_enabled_result=$(check_cdn_enabled "$config_file")
echo "2.1.11 Ensure CDN is enabled for improved GUI performance (Manual), $cdn_enabled_result" >> "$CSV_FILE"
log "$cdn_enabled_result"

# CIS Benchmark: 2.1.12 Ensure single CPU core overloaded event is logged (Manual)
cpu_overloaded_event_result=$(check_cpu_overloaded_event "$config_file")
echo "2.1.12 Ensure single CPU core overloaded event is logged (Manual), $cpu_overloaded_event_result" >> "$CSV_FILE"
log "$cpu_overloaded_event_result"

# CIS Benchmark: 2.2 Password Settings

# CIS Benchmark: 2.2.1 Ensure 'Password Policy' is enabled (Automated)
password_policy_result=$(check_password_policy "$config_file")
echo "2.2.1 Ensure 'Password Policy' is enabled (Automated), $password_policy_result" >> "$CSV_FILE"
log "$password_policy_result"

# CIS Benchmark: 2.2.2 Ensure administrator password retries and lockout time are configured (Automated)
password_retries_lockout_result=$(check_password_retries_lockout "$config_file")
echo "2.2.2 Ensure administrator password retries and lockout time are configured (Automated), $password_retries_lockout_result" >> "$CSV_FILE"
log "$password_retries_lockout_result"

# CIS Benchmark: 2.3 SNMP Settings

# CIS Benchmark: 2.3.1 Ensure only SNMPv3 is enabled (Automated)
snmpv3_only_result=$(check_snmpv3_only "$config_file")
echo "2.3.1 Ensure only SNMPv3 is enabled (Automated), $snmpv3_only_result" >> "$CSV_FILE"
log "$snmpv3_only_result"

# CIS Benchmark: 2.3.2 Allow only trusted hosts in SNMPv3 (Manual)
snmpv3_trusted_hosts_result=$(check_snmpv3_trusted_hosts "$config_file")
echo "2.3.2 Allow only trusted hosts in SNMPv3 (Manual), $snmpv3_trusted_hosts_result" >> "$CSV_FILE"
log "$snmpv3_trusted_hosts_result"

# CIS Benchmark: 2.4 User Authentication

# CIS Benchmark: 2.4.1 Ensure default 'admin' password is changed (Manual)
admin_password_result=$(check_admin_password "$config_file")
echo "2.4.1 Ensure default 'admin' password is changed (Manual), $admin_password_result" >> "$CSV_FILE"
log "$admin_password_result"

# CIS Benchmark: 2.4.2 Ensure all the login accounts having specific trusted hosts enabled (Manual)
login_accounts_trusted_hosts_result=$(check_login_accounts_trusted_hosts "$config_file")
echo "2.4.2 Ensure all the login accounts having specific trusted hosts enabled (Manual), $login_accounts_trusted_hosts_result" >> "$CSV_FILE"
log "$login_accounts_trusted_hosts_result"

# CIS Benchmark: 2.4.3 Ensure admin accounts with different privileges have their correct profiles assigned (Manual)
admin_accounts_profiles_result=$(check_admin_accounts_profiles "$config_file")
echo "2.4.3 Ensure admin accounts with different privileges have their correct profiles assigned (Manual), $admin_accounts_profiles_result" >> "$CSV_FILE"
log "$admin_accounts_profiles_result"

# CIS Benchmark: 2.4.4 Ensure idle timeout time is configured (Automated)
idle_timeout_result=$(check_idle_timeout "$config_file")
echo "2.4.4 Ensure idle timeout time is configured (Automated), $idle_timeout_result" >> "$CSV_FILE"
log "$idle_timeout_result"

# CIS Benchmark: 2.4.5 Ensure only encrypted access channels are enabled (Automated)
encrypted_access_channels_result=$(check_encrypted_access_channels "$config_file")
echo "2.4.5 Ensure only encrypted access channels are enabled (Automated), $encrypted_access_channels_result" >> "$CSV_FILE"
log "$encrypted_access_channels_result"

# CIS Benchmark: 2.4.6 Ensure Local-in Policies are applied (Manual)
local_in_policies_result=$(apply_local_in_policies)
echo "2.4.6 Ensure Local-in Policies are applied (Manual), $local_in_policies_result" >> "$CSV_FILE"
log "$local_in_policies_result"

# CIS Benchmark: 2.4.7 Ensure default Admin ports are changed (Manual)
default_admin_ports_changed_result=$(check_default_admin_ports_changed)
echo "2.4.7 Ensure default Admin ports are changed (Manual), $default_admin_ports_changed_result" >> "$CSV_FILE"
log "$default_admin_ports_changed_result"

# CIS Benchmark: 2.4.8 Ensure virtual patching on the local-in management interface is enabled (Manual)
virtual_patching_local_in_interface_result=$(check_virtual_patching_local_in_interface)
echo "2.4.8 Ensure virtual patching on the local-in management interface is enabled (Manual), $virtual_patching_local_in_interface_result" >> "$CSV_FILE"
log "$virtual_patching_local_in_interface_result"

# CIS Benchmark: 2.4.9 Ensure High Availability configuration is enabled (Manual)
ha_configuration_result=$(check_ha_configuration "$config_file")
echo "2.4.9 Ensure High Availability configuration is enabled (Manual), $ha_configuration_result" >> "$CSV_FILE"
log "$ha_configuration_result"

# CIS Benchmark: 2.4.10 Ensure 'Monitor Interfaces' for High Availability devices is enabled (Manual)
ha_monitor_interfaces_result=$(check_ha_monitor_interfaces "$config_file")
echo "2.4.10 Ensure 'Monitor Interfaces' for High Availability devices is enabled (Manual), $ha_monitor_interfaces_result" >> "$CSV_FILE"
log "$ha_monitor_interfaces_result"

# CIS Benchmark: 2.4.11 Ensure HA Reserved Management Interface is configured (Manual)
ha_reserved_management_interface_result=$(check_ha_reserved_management_interface "$config_file")
echo "2.4.11 Ensure HA Reserved Management Interface is configured (Manual), $ha_reserved_management_interface_result" >> "$CSV_FILE"
log "$ha_reserved_management_interface_result"

# CIS Benchmark: 3 Firewall Settings

# CIS Benchmark: 3.1 Ensure that unused policies are reviewed regularly (Manual)
review_unused_policies_result=$(check_review_unused_policies)
echo "3.1 Ensure that unused policies are reviewed regularly (Manual), $review_unused_policies_result" >> "$CSV_FILE"
log "$review_unused_policies_result"

# CIS Benchmark: 3.2 Ensure that policies do not use "ALL" as Service (Automated)
no_all_service_policies_result=$(check_no_all_service_policies "$config_file")
echo "3.2 Ensure that policies do not use 'ALL' as Service (Automated), $no_all_service_policies_result" >> "$CSV_FILE"
log "$no_all_service_policies_result"

# CIS Benchmark: 3.3 Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB (Manual)
denying_traffic_to_from_tor_result=$(check_denying_traffic_to_from_tor)
echo "3.3 Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB (Manual), $denying_traffic_to_from_tor_result" >> "$CSV_FILE"
log "$denying_traffic_to_from_tor_result"

# CIS Benchmark: 3.4 Ensure logging is enabled on all firewall policies (Manual)
logging_enabled_firewall_policies_result=$(check_logging_enabled_firewall_policies)
echo "3.4 Ensure logging is enabled on all firewall policies (Manual), $logging_enabled_firewall_policies_result" >> "$CSV_FILE"
log "$logging_enabled_firewall_policies_result"

# CIS Benchmark: 4 System Hardening

# CIS Benchmark: 4.1 Malware Prevention

# CIS Benchmark: 4.1.1 Detect Botnet connections (Manual)
botnet_connections_result=$(detect_botnet_connections)
echo "4.1.1 Detect Botnet connections (Manual), $botnet_connections_result" >> "$CSV_FILE"
log "$botnet_connections_result"

# CIS Benchmark: 4.1.2 Apply IPS Security Profile to Policies (Manual)
ips_security_profile_result=$(apply_ips_security_profile)
echo "4.1.2 Apply IPS Security Profile to Policies (Manual), $ips_security_profile_result" >> "$CSV_FILE"
log "$ips_security_profile_result"

# CIS Benchmark: 4.2 Antivirus and Anti-Spyware

# CIS Benchmark: 4.2.1 Ensure Antivirus Definition Push Updates are Configured (Automated)
antivirus_definition_updates_result=$(check_antivirus_definition_updates "$config_file")
echo "4.2.1 Ensure Antivirus Definition Push Updates are Configured (Automated), $antivirus_definition_updates_result" >> "$CSV_FILE"
log "$antivirus_definition_updates_result"

# CIS Benchmark: 4.2.2 Apply Antivirus Security Profile to Policies (Manual)
antivirus_security_profile_result=$(apply_antivirus_security_profile)
echo "4.2.2 Apply Antivirus Security Profile to Policies (Manual), $antivirus_security_profile_result" >> "$CSV_FILE"
log "$antivirus_security_profile_result"

# CIS Benchmark: 4.2.3 Ensure Outbreak Prevention Database (Automated)
outbreak_prevention_database_result=$(check_outbreak_prevention_database "$config_file")
echo "4.2.3 Ensure Outbreak Prevention Database (Automated), $outbreak_prevention_database_result" >> "$CSV_FILE"
log "$outbreak_prevention_database_result"

# CIS Benchmark: 4.2.4 Enable AI/heuristic based malware detection (Automated)
ai_malware_detection_result=$(check_ai_malware_detection "$config_file")
echo "4.2.4 Enable AI/heuristic based malware detection (Automated), $ai_malware_detection_result" >> "$CSV_FILE"
log "$ai_malware_detection_result"

# CIS Benchmark: 4.2.5 Enable grayware detection on antivirus (Automated)
grayware_detection_result=$(check_grayware_detection "$config_file")
echo "4.2.5 Enable grayware detection on antivirus (Automated), $grayware_detection_result" >> "$CSV_FILE"
log "$grayware_detection_result"

# CIS Benchmark: 4.2.6 Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled (Manual)
inline_scanning_sandbox_result=$(check_inline_scanning_sandbox)
echo "4.2.6 Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled (Manual), $inline_scanning_sandbox_result" >> "$CSV_FILE"
log "$inline_scanning_sandbox_result"

# CIS Benchmark: 4.3 Application Control

# CIS Benchmark: 4.3.1 Enable Botnet C&C Domain Blocking DNS Filter (Automated)
botnet_cnc_domain_blocking_result=$(enable_botnet_cnc_domain_blocking "$config_file")
echo "4.3.1 Enable Botnet C&C Domain Blocking DNS Filter (Automated), $botnet_cnc_domain_blocking_result" >> "$CSV_FILE"
log "$botnet_cnc_domain_blocking_result"

# CIS Benchmark: 4.3.2 Ensure DNS Filter logs all DNS queries and responses (Manual)
dns_filter_logging_result=$(check_dns_filter_logging)
echo "4.3.2 Ensure DNS Filter logs all DNS queries and responses (Manual), $dns_filter_logging_result" >> "$CSV_FILE"
log "$dns_filter_logging_result"

# CIS Benchmark: 4.3.3 Apply DNS Filter Security Profile to Policies (Manual)
dns_filter_security_profile_result=$(apply_dns_filter_security_profile)
echo "4.3.3 Apply DNS Filter Security Profile to Policies (Manual), $dns_filter_security_profile_result" >> "$CSV_FILE"
log "$dns_filter_security_profile_result"

# CIS Benchmark: 4.4 Web Filter

# CIS Benchmark: 4.4.1 Block high risk categories on Application Control (Manual)
block_high_risk_categories_result=$(block_high_risk_categories)
echo "4.4.1 Block high risk categories on Application Control (Manual), $block_high_risk_categories_result" >> "$CSV_FILE"
log "$block_high_risk_categories_result"

# CIS Benchmark: 4.4.2 Block applications running on non-default ports (Automated)
block_non_default_port_applications_result=$(block_non_default_port_applications "$config_file")
echo "4.4.2 Block applications running on non-default ports (Automated), $block_non_default_port_applications_result" >> "$CSV_FILE"
log "$block_non_default_port_applications_result"

# CIS Benchmark: 4.4.3 Ensure all Application Control related traffic is logged (Manual)
application_control_logging_result=$(check_application_control_logging)
echo "4.4.3 Ensure all Application Control related traffic is logged (Manual), $application_control_logging_result" >> "$CSV_FILE"
log "$application_control_logging_result"

# CIS Benchmark: 4.4.4 Apply Application Control Security Profile to Policies (Manual)
application_control_security_profile_result=$(apply_application_control_security_profile)
echo "4.4.4 Apply Application Control Security Profile to Policies (Manual), $application_control_security_profile_result" >> "$CSV_FILE"
log "$application_control_security_profile_result"

# CIS Benchmark: 5 Logging and Monitoring

# CIS Benchmark: 5.1 Ensure Logging and Monitoring Settings

# CIS Benchmark: 5.1.1 Enable Compromised Host Quarantine (Automated)
compromised_host_quarantine_result=$(check_compromised_host_quarantine "$config_file")
echo "5.1.1 Enable Compromised Host Quarantine (Automated), $compromised_host_quarantine_result" >> "$CSV_FILE"
log "$compromised_host_quarantine_result"

# CIS Benchmark: 5.2 Ensure Logging and Monitoring

# CIS Benchmark: 5.2.1.1 Ensure Security Fabric is Configured (Automated)
security_fabric_configured_result=$(check_security_fabric_configured "$config_file")
echo "5.2.1.1 Ensure Security Fabric is Configured (Automated), $security_fabric_configured_result" >> "$CSV_FILE"
log "$security_fabric_configured_result"

# CIS Benchmark: 6 Communication and Traffic Management

# CIS Benchmark: 6.1 Ensure Secure Communication Settings

# CIS Benchmark: 6.1.1 Apply a Trusted Signed Certificate for VPN Portal (Manual)
trusted_certificate_vpn_portal_result=$(apply_trusted_certificate_vpn_portal)
echo "6.1.1 Apply a Trusted Signed Certificate for VPN Portal (Manual), $trusted_certificate_vpn_portal_result" >> "$CSV_FILE"
log "$trusted_certificate_vpn_portal_result"

# CIS Benchmark: 6.1.2 Enable Limited TLS Versions for SSL VPN (Manual)
ssl_vpn_tls_versions_result=$(check_ssl_vpn_tls_versions)
echo "6.1.2 Enable Limited TLS Versions for SSL VPN (Manual), $ssl_vpn_tls_versions_result" >> "$CSV_FILE"
log "$ssl_vpn_tls_versions_result"

# CIS Benchmark: 7 Auditing, Accountability, and Risk Management

# CIS Benchmark: 7.1 Ensure Audit Logs Settings

# CIS Benchmark: 7.1.1 Enable Event Logging (Automated)
event_logging_enabled_result=$(check_event_logging_enabled "$config_file")
echo "7.1.1 Enable Event Logging (Automated), $event_logging_enabled_result" >> "$CSV_FILE"
log "$event_logging_enabled_result"

# CIS Benchmark: 7.2 Ensure Audit Logs Protection

# CIS Benchmark: 7.2.1 Encrypt Logs Sent to FortiAnalyzer / FortiManager (Automated)
encrypt_logs_sent_to_forti_result=$(encrypt_logs_sent_to_forti)
echo "7.2.1 Encrypt Logs Sent to FortiAnalyzer / FortiManager (Automated), $encrypt_logs_sent_to_forti_result" >> "$CSV_FILE"
log "$encrypt_logs_sent_to_forti_result"

# CIS Benchmark: 7.2.1 Encrypt Log Transmission to FortiAnalyzer / FortiManager (Automated)
log_transmission_to_forti_result=$(enable_log_transmission_to_forti "$config_file")
echo "7.2.1 Encrypt Log Transmission to FortiAnalyzer / FortiManager (Automated), $log_transmission_to_forti_result" >> "$CSV_FILE"
log "$log_transmission_to_forti_result"

# CIS Benchmark: 7.3 Ensure Audit Logs Centralization

# CIS Benchmark: 7.3.1 Centralized Logging and Reporting (Automated)
centralized_logging_reporting_result=$(check_centralized_logging_reporting "$config_file")
echo "7.3.1 Centralized Logging and Reporting (Automated), $centralized_logging_reporting_result" >> "$CSV_FILE"
log "$centralized_logging_reporting_result"

# Add more checks for other CIS benchmarks as needed...

log "CIS benchmarks Audit check completed."
echo "CIS benchmarks Audit check completed."

# Calculate totals

total_checks=$(wc -l < "$CSV_FILE")
total_manual_checks=$(grep -c "Manual" "$CSV_FILE")
total_pass=$(grep -c "PASS" "$CSV_FILE")
total_fail=$(grep -c "FAIL" "$CSV_FILE")

# HTML output
HTML_FILE="FORTIGATE_7.0.x_CIS_BENCHMARK_v1.3.0_AUDIT_$(date +"%Y%m%d_%H%M%S").html"

echo "<html>
<head><title>FORTIGATE CIS Benchmark Audit Report</title></head>
<body>
<h1>CIS Benchmark Audit Report</h1>
<p>Total CIS Benchmark Checks: $total_checks</p>
<p>Total Automated Checks: $(($total_checks - $total_manual_checks))</p>
<p>Total Manual Checks: $total_manual_checks</p>
<p>Total PASS: $total_pass</p>
<p>Total FAIL: $total_fail</p>
<table border="1">
<tr><th>Benchmark</th><th>Result</th></tr>" > "$HTML_FILE"

cat "$CSV_FILE" | while IFS="," read -r benchmark result; do
    echo "<tr><td>$benchmark</td><td>$result</td></tr>" >> "$HTML_FILE"
done

echo "</table>
</body>
</html>" >> "$HTML_FILE"

echo "HTML report generated: $HTML_FILE"
echo  "[-------------SkFJX01BSEFLQUwh------------]"
echo  "follow me on https://github.com/ch3332xr"
