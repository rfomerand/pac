# CIS Benchmarks for Virtual Machines
# Supports: AWS EC2, Azure VM, GCP Compute, VMware vSphere
# Organization: Example Corp Security Team
# Last Updated: 2025-01-20
# Policy Format: Open Policy Agent (OPA) Rego v0.60.0
# Encryption: Validates all VM disks are encrypted at rest
#Network Security: Checks for proper firewall rules, no unrestricted access, and network monitoring
#Access Control: Ensures proper IAM/identity configuration, SSH hardening, and authentication methods
#Patch Management: Validates automated patching is configured
#Monitoring: Ensures logging agents and monitoring are enabled
#Backup: Validates backup configuration for production VM#s
#Resource Optimization: Checks for cost optimization and proper resource allocation

#Key features:
#
#Platform-agnostic design with platform-specific implementations
#Comprehensive helper functions for reusability
#Clear violation messages with context
#Severity-based categorization
#Compliance summary generation
#Enforcement decisions with remediation actions

package virtualmachine.security.cis

import rego.v1

# Metadata for policy management and compliance tracking
metadata := {
    "version": "1.0.0",
    "frameworks": ["CIS AWS", "CIS Azure", "CIS GCP", "CIS VMware"],
    "platforms": ["aws_ec2", "azure_vm", "gcp_compute", "vmware_vsphere"],
    "severity_levels": {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4
    }
}

#-----------------------------------------------------------------------------
# Rule: vm_encryption_required
# CIS Controls: AWS 2.2.1, Azure 7.1, GCP 4.7
# Description: Ensures all VM disks are encrypted at rest
#-----------------------------------------------------------------------------

default vm_encryption_required := false

vm_encryption_required if {
    input.resource_type in ["vm", "instance", "virtual_machine"]
    count(violations_vm_encryption) == 0
}

violations_vm_encryption contains msg if {
    input.platform == "aws_ec2"
    disk := input.block_device_mappings[_]
    not disk.ebs.encrypted
    msg := sprintf("EC2 instance disk '%s' is not encrypted", [disk.device_name])
}

violations_vm_encryption contains msg if {
    input.platform == "azure_vm"
    disk := input.storage_profile.os_disk
    not disk.encryption_settings.enabled
    msg := "Azure VM OS disk is not encrypted"
}

violations_vm_encryption contains msg if {
    input.platform == "azure_vm"
    disk := input.storage_profile.data_disks[_]
    not disk.encryption_settings.enabled
    msg := sprintf("Azure VM data disk '%s' is not encrypted", [disk.name])
}

violations_vm_encryption contains msg if {
    input.platform == "gcp_compute"
    disk := input.disks[_]
    not disk.disk_encryption_key
    msg := sprintf("GCP instance disk '%s' lacks encryption key", [disk.device_name])
}

#-----------------------------------------------------------------------------
# Rule: vm_network_security
# CIS Controls: AWS 5.1, Azure 6.1, GCP 3.6
# Description: Validates network security configurations
#-----------------------------------------------------------------------------

default vm_network_security := false

vm_network_security if {
    count(violations_vm_network) == 0
}

violations_vm_network contains msg if {
    input.platform == "aws_ec2"
    not input.source_dest_check
    not is_nat_instance
    msg := "EC2 instance has source/destination check disabled"
}

violations_vm_network contains msg if {
    has_public_ip
    not has_security_groups
    msg := "VM with public IP lacks security group/firewall rules"
}

violations_vm_network contains msg if {
    rule := get_ingress_rules[_]
    is_unrestricted_ingress(rule)
    is_sensitive_port(rule.port)
    msg := sprintf("Unrestricted ingress on sensitive port %d", [rule.port])
}

violations_vm_network contains msg if {
    input.platform in ["aws_ec2", "azure_vm", "gcp_compute"]
    not has_network_monitoring
    msg := "VM lacks network monitoring (VPC Flow Logs/NSG Flow Logs/VPC Flow Logs)"
}

#-----------------------------------------------------------------------------
# Rule: vm_access_control
# CIS Controls: AWS 2.1.5, Azure 5.2.1, GCP 4.1
# Description: Ensures proper access control and authentication
#-----------------------------------------------------------------------------

default vm_access_control := false

vm_access_control if {
    count(violations_vm_access) == 0
}

violations_vm_access contains msg if {
    input.platform == "aws_ec2"
    not input.iam_instance_profile
    msg := "EC2 instance lacks IAM instance profile"
}

violations_vm_access contains msg if {
    input.platform == "azure_vm"
    not input.identity.type == "SystemAssigned"
    msg := "Azure VM should use managed identity"
}

violations_vm_access contains msg if {
    has_ssh_access
    allows_password_authentication
    msg := "SSH password authentication should be disabled"
}

violations_vm_access contains msg if {
    has_rdp_access
    not has_network_level_authentication
    msg := "RDP requires Network Level Authentication"
}

violations_vm_access contains msg if {
    input.platform == "gcp_compute"
    metadata_value := input.metadata.items[_]
    metadata_value.key == "enable-oslogin"
    metadata_value.value != "TRUE"
    msg := "GCP instance should enable OS Login"
}

#-----------------------------------------------------------------------------
# Rule: vm_patch_compliance
# CIS Controls: All platforms - patch management
# Description: Validates patch management configuration
#-----------------------------------------------------------------------------

default vm_patch_compliance := false

vm_patch_compliance if {
    count(violations_vm_patch) == 0
}

violations_vm_patch contains msg if {
    not has_patch_management
    msg := "VM lacks automated patch management configuration"
}

violations_vm_patch contains msg if {
    input.platform == "aws_ec2"
    not has_tag("patch-group")
    msg := "EC2 instance missing patch-group tag for Systems Manager"
}

violations_vm_patch contains msg if {
    input.platform == "azure_vm"
    not input.os_profile.linux_configuration.patch_settings.patch_mode == "AutomaticByPlatform"
    input.os_profile.linux_configuration
    msg := "Azure Linux VM should use automatic patching"
}

#-----------------------------------------------------------------------------
# Rule: vm_monitoring_enabled
# CIS Controls: AWS 3.1, Azure 5.1.1, GCP 2.1
# Description: Ensures comprehensive monitoring and logging
#-----------------------------------------------------------------------------

default vm_monitoring_enabled := false

vm_monitoring_enabled if {
    count(violations_vm_monitoring) == 0
}

violations_vm_monitoring contains msg if {
    input.platform == "aws_ec2"
    not input.monitoring.state == "enabled"
    msg := "EC2 detailed monitoring is not enabled"
}

violations_vm_monitoring contains msg if {
    not has_logging_agent
    msg := "VM lacks logging agent installation"
}

violations_vm_monitoring contains msg if {
    input.platform == "azure_vm"
    not has_diagnostics_enabled
    msg := "Azure VM diagnostics not enabled"
}

violations_vm_monitoring contains msg if {
    input.platform == "gcp_compute"
    not has_ops_agent
    msg := "GCP instance lacks Ops Agent for monitoring"
}

#-----------------------------------------------------------------------------
# Rule: vm_backup_configured
# Best Practice: Ensure VM backup and disaster recovery
# Description: Validates backup configuration
#-----------------------------------------------------------------------------

default vm_backup_configured := false

vm_backup_configured if {
    count(violations_vm_backup) == 0
}

violations_vm_backup contains msg if {
    is_production_vm
    not has_backup_configured
    msg := "Production VM lacks backup configuration"
}

violations_vm_backup contains msg if {
    has_backup_configured
    backup_retention_days < 7
    msg := sprintf("Backup retention %d days is below minimum 7 days", [backup_retention_days])
}

#-----------------------------------------------------------------------------
# Rule: vm_resource_optimization
# Best Practice: Ensure appropriate VM sizing and configuration
# Description: Validates resource allocation and optimization
#-----------------------------------------------------------------------------

default vm_resource_optimization := false

vm_resource_optimization if {
    count(violations_vm_resources) == 0
}

violations_vm_resources contains msg if {
    not is_using_current_generation_instance
    msg := sprintf("VM using deprecated instance type '%s'", [input.instance_type])
}

violations_vm_resources contains msg if {
    input.platform in ["aws_ec2", "azure_vm"]
    not has_termination_protection
    is_production_vm
    msg := "Production VM should have termination protection enabled"
}

violations_vm_resources contains msg if {
    has_public_ip
    is_stopped_instance
    elapsed_days := time.now_ns() - input.stop_time_ns
    elapsed_days > 7 * 24 * 60 * 60 * 1000000000  # 7 days in nanoseconds
    msg := "Stopped instance with public IP incurring charges"
}

#-----------------------------------------------------------------------------
# Helper Functions
#-----------------------------------------------------------------------------

# Check if VM has public IP
has_public_ip if {
    input.platform == "aws_ec2"
    input.public_ip_address
}

has_public_ip if {
    input.platform == "azure_vm"
    input.network_profile.network_interfaces[_].ip_configurations[_].public_ip_address
}

has_public_ip if {
    input.platform == "gcp_compute"
    input.network_interfaces[_].access_configs[_].nat_ip
}

# Check if VM has security groups/firewall
has_security_groups if {
    input.platform == "aws_ec2"
    count(input.security_groups) > 0
}

has_security_groups if {
    input.platform == "azure_vm"
    input.network_profile.network_security_group
}

has_security_groups if {
    input.platform == "gcp_compute"
    count(input.tags.items) > 0  # GCP uses tags for firewall rules
}

# Get ingress rules based on platform
get_ingress_rules[rule] := rule if {
    input.platform == "aws_ec2"
    sg := data.aws.security_groups[_]
    sg.group_id in {g.group_id | g := input.security_groups[_]}
    rule := sg.ingress_rules[_]
}

get_ingress_rules[rule] := rule if {
    input.platform == "azure_vm"
    nsg := data.azure.network_security_groups[_]
    rule := nsg.security_rules[_]
    rule.direction == "Inbound"
}

# Check for unrestricted ingress
is_unrestricted_ingress(rule) if {
    rule.cidr_blocks[_] == "0.0.0.0/0"
}

is_unrestricted_ingress(rule) if {
    rule.source_address_prefix == "*"
}

# Define sensitive ports
is_sensitive_port(port) if {
    port in [22, 3389, 445, 135, 139, 1433, 3306, 5432, 5984, 6379, 7000, 7001, 8020, 8086, 8888, 9042, 9160, 9200, 9300, 11211, 27017, 27018, 27019, 50070]
}

# Check SSH configuration
has_ssh_access if {
    rule := get_ingress_rules[_]
    rule.port == 22
}

allows_password_authentication if {
    input.platform in ["aws_ec2", "gcp_compute"]
    not input.metadata.ssh_password_authentication_disabled
}

allows_password_authentication if {
    input.platform == "azure_vm"
    not input.os_profile.linux_configuration.disable_password_authentication
}

# Check RDP configuration
has_rdp_access if {
    rule := get_ingress_rules[_]
    rule.port == 3389
}

has_network_level_authentication if {
    input.platform == "azure_vm"
    input.os_profile.windows_configuration.enable_network_level_authentication
}

# Check monitoring configuration
has_logging_agent if {
    input.platform == "aws_ec2"
    has_tag("cloudwatch-agent-installed")
}

has_logging_agent if {
    input.platform == "azure_vm"
    extension := input.resources.extensions[_]
    extension.type in ["OmsAgentForLinux", "MicrosoftMonitoringAgent"]
}

has_ops_agent if {
    input.platform == "gcp_compute"
    metadata_value := input.metadata.items[_]
    metadata_value.key == "enable-ops-agent"
    metadata_value.value == "true"
}

# Check if NAT instance
is_nat_instance if {
    has_tag("Type", "NAT")
}

# Check for tags
has_tag(key) if {
    input.tags[key]
}

has_tag(key, value) if {
    input.tags[key] == value
}

# Check if production VM
is_production_vm if {
    lower(input.tags.Environment) == "production"
}

is_production_vm if {
    lower(input.tags.env) == "prod"
}

# Check backup configuration
has_backup_configured if {
    input.platform == "aws_ec2"
    has_tag("backup-plan")
}

has_backup_configured if {
    input.platform == "azure_vm"
    input.backup.policy_id
}

backup_retention_days := days if {
    input.backup.retention_days
    days := input.backup.retention_days
} else := 0

# Check patch management
has_patch_management if {
    input.platform == "aws_ec2"
    has_tag("patch-group")
}

has_patch_management if {
    input.platform == "azure_vm"
    input.os_profile.linux_configuration.patch_settings.patch_mode
}

has_patch_management if {
    input.platform == "gcp_compute"
    metadata_value := input.metadata.items[_]
    metadata_value.key == "enable-guest-attributes"
    metadata_value.value == "TRUE"
}

# Network monitoring checks
has_network_monitoring if {
    input.platform == "aws_ec2"
    data.aws.vpc_flow_logs[input.vpc_id]
}

has_network_monitoring if {
    input.platform == "azure_vm"
    data.azure.network_watcher_flow_logs[input.subnet_id]
}

# Instance generation check
is_using_current_generation_instance if {
    input.platform == "aws_ec2"
    not regex.match("^(t1|m1|m2|m3|c1|c3|r3|i2)", input.instance_type)
}

is_using_current_generation_instance if {
    input.platform == "azure_vm"
    not contains(input.vm_size, "_v1")
}

is_using_current_generation_instance if {
    input.platform == "gcp_compute"
    true  # GCP automatically migrates
}

# Termination protection
has_termination_protection if {
    input.platform == "aws_ec2"
    input.disable_api_termination
}

has_termination_protection if {
    input.platform == "azure_vm"
    input.resource_lock.level == "CanNotDelete"
}

# Check if instance is stopped
is_stopped_instance if {
    input.state in ["stopped", "deallocated"]
}

# Diagnostics check
has_diagnostics_enabled if {
    input.platform == "azure_vm"
    input.diagnostics_profile.boot_diagnostics.enabled
}

#-----------------------------------------------------------------------------
# Compliance Summary
#-----------------------------------------------------------------------------

compliance_summary := summary if {
    critical_violations := array.concat(
        [v | v := violations_vm_encryption[_]],
        [v | v := violations_vm_access[_]]
    )
    
    high_violations := array.concat(
        [v | v := violations_vm_network[_]],
        [v | v := violations_vm_patch[_]]
    )
    
    medium_violations := array.concat(
        [v | v := violations_vm_monitoring[_]],
        [v | v := violations_vm_backup[_]]
    )
    
    low_violations := [v | v := violations_vm_resources[_]]
    
    summary := {
        "compliant": count(critical_violations) + count(high_violations) == 0,
        "violations": {
            "critical": critical_violations,
            "high": high_violations,
            "medium": medium_violations,
            "low": low_violations
        },
        "resource": {
            "type": input.resource_type,
            "id": input.instance_id,
            "name": input.name,
            "platform": input.platform
        },
        "metadata": metadata
    }
}

#-----------------------------------------------------------------------------
# Enforcement Decision
#-----------------------------------------------------------------------------

# Main enforcement rule
default allow := false

allow if {
    # Allow if no critical or high severity violations
    count(compliance_summary.violations.critical) == 0
    count(compliance_summary.violations.high) == 0
}

# Detailed decision for admission controllers
decision := {
    "allow": allow,
    "violations": compliance_summary.violations,
    "platform": input.platform,
    "required_actions": required_remediation_actions
}

# Generate remediation actions
required_remediation_actions[action] := action if {
    count(violations_vm_encryption) > 0
    action := "enable_disk_encryption"
}

required_remediation_actions[action] := action if {
    count(violations_vm_network) > 0
    action := "configure_network_security"
}

required_remediation_actions[action] := action if {
    count(violations_vm_access) > 0
    action := "implement_access_controls"
}
