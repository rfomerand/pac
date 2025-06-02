# Test suite for Virtual Machine Security Policies
# Run with: opa test -v policies/ tests/

package virtualmachine.security.cis_test

import rego.v1
import data.virtualmachine.security.cis

#-----------------------------------------------------------------------------
# Test: VM Encryption - AWS EC2
#-----------------------------------------------------------------------------

test_aws_ec2_encryption_compliant if {
    result := cis.vm_encryption_required with input as {
        "resource_type": "instance",
        "platform": "aws_ec2",
        "instance_id": "i-1234567890abcdef0",
        "block_device_mappings": [
            {
                "device_name": "/dev/sda1",
                "ebs": {
                    "encrypted": true,
                    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678"
                }
            },
            {
                "device_name": "/dev/sdf",
                "ebs": {
                    "encrypted": true
                }
            }
        ]
    }
    
    result == true
}

test_aws_ec2_encryption_violation if {
    violations := cis.violations_vm_encryption with input as {
        "platform": "aws_ec2",
        "block_device_mappings": [
            {
                "device_name": "/dev/sda1",
                "ebs": {"encrypted": false}
            }
        ]
    }
    
    count(violations) == 1
    violations[_] == "EC2 instance disk '/dev/sda1' is not encrypted"
}

#-----------------------------------------------------------------------------
# Test: VM Encryption - Azure
#-----------------------------------------------------------------------------

test_azure_vm_encryption_compliant if {
    result := cis.vm_encryption_required with input as {
        "resource_type": "virtual_machine",
        "platform": "azure_vm",
        "storage_profile": {
            "os_disk": {
                "name": "osdisk",
                "encryption_settings": {"enabled": true}
            },
            "data_disks": [
                {
                    "name": "datadisk1",
                    "encryption_settings": {"enabled": true}
                }
            ]
        }
    }
    
    result == true
}

test_azure_vm_data_disk_encryption_violation if {
    violations := cis.violations_vm_encryption with input as {
        "platform": "azure_vm",
        "storage_profile": {
            "os_disk": {
                "encryption_settings": {"enabled": true}
            },
            "data_disks": [
                {
                    "name": "datadisk1",
                    "encryption_settings": {"enabled": false}
                }
            ]
        }
    }
    
    count(violations) == 1
    violations[_] == "Azure VM data disk 'datadisk1' is not encrypted"
}

#-----------------------------------------------------------------------------
# Test: VM Network Security
#-----------------------------------------------------------------------------

test_network_security_unrestricted_ssh if {
    violations := cis.violations_vm_network with input as {
        "platform": "aws_ec2",
        "public_ip_address": "1.2.3.4",
        "security_groups": [{"group_id": "sg-12345"}]
    } with data.aws.security_groups as [{
        "group_id": "sg-12345",
        "ingress_rules": [{
            "port": 22,
            "cidr_blocks": ["0.0.0.0/0"]
        }]
    }]
    
    count([v | v := violations[_]; contains(v, "Unrestricted ingress on sensitive port 22")]) == 1
}

test_network_security_source_dest_check if {
    violations := cis.violations_vm_network with input as {
        "platform": "aws_ec2",
        "source_dest_check": false,
        "tags": {}
    }
    
    violations[_] == "EC2 instance has source/destination check disabled"
}

test_network_security_nat_instance_allowed if {
    violations := cis.violations_vm_network with input as {
        "platform": "aws_ec2",
        "source_dest_check": false,
        "tags": {"Type": "NAT"}
    }
    
    # NAT instances are allowed to have source/dest check disabled
    not "EC2 instance has source/destination check disabled" in violations
}

#-----------------------------------------------------------------------------
# Test: VM Access Control
#-----------------------------------------------------------------------------

test_access_control_iam_profile_missing if {
    violations := cis.violations_vm_access with input as {
        "platform": "aws_ec2",
        "iam_instance_profile": null
    }
    
    violations[_] == "EC2 instance lacks IAM instance profile"
}

test_access_control_azure_managed_identity if {
    violations := cis.violations_vm_access with input as {
        "platform": "azure_vm",
        "identity": {"type": "None"}
    }
    
    violations[_] == "Azure VM should use managed identity"
}

test_access_control_ssh_password_auth if {
    violations := cis.violations_vm_access with input as {
        "platform": "aws_ec2",
        "metadata": {
            "ssh_password_authentication_disabled": false
        }
    } with data.aws.security_groups as [{
        "group_id": "sg-12345",
        "ingress_rules": [{"port": 22, "cidr_blocks": ["10.0.0.0/8"]}]
    }]
    
    count([v | v := violations[_]; v == "SSH password authentication should be disabled"]) == 1
}

test_access_control_gcp_oslogin if {
    violations := cis.violations_vm_access with input as {
        "platform": "gcp_compute",
        "metadata": {
            "items": [{
                "key": "enable-oslogin",
                "value": "FALSE"
            }]
        }
    }
    
    violations[_] == "GCP instance should enable OS Login"
}

#-----------------------------------------------------------------------------
# Test: VM Patch Compliance
#-----------------------------------------------------------------------------

test_patch_compliance_aws_tags if {
    violations := cis.violations_vm_patch with input as {
        "platform": "aws_ec2",
        "tags": {"Name": "web-server"}
    }
    
    # Should have both violations
    count(violations) == 2
    violations[_] == "VM lacks automated patch management configuration"
    violations[_] == "EC2 instance missing patch-group tag for Systems Manager"
}

test_patch_compliance_azure_automatic if {
    violations := cis.violations_vm_patch with input as {
        "platform": "azure_vm",
        "os_profile": {
            "linux_configuration": {
                "patch_settings": {
                    "patch_mode": "Manual"
                }
            }
        }
    }
    
    violations[_] == "Azure Linux VM should use automatic patching"
}

#-----------------------------------------------------------------------------
# Test: VM Monitoring
#-----------------------------------------------------------------------------

test_monitoring_ec2_detailed if {
    violations := cis.violations_vm_monitoring with input as {
        "platform": "aws_ec2",
        "monitoring": {"state": "disabled"},
        "tags": {}
    }
    
    count(violations) == 2
    violations[_] == "EC2 detailed monitoring is not enabled"
    violations[_] == "VM lacks logging agent installation"
}

test_monitoring_gcp_ops_agent if {
    violations := cis.violations_vm_monitoring with input as {
        "platform": "gcp_compute",
        "metadata": {"items": []}
    }
    
    violations[_] == "GCP instance lacks Ops Agent for monitoring"
}

#-----------------------------------------------------------------------------
# Test: VM Backup
#-----------------------------------------------------------------------------

test_backup_production_required if {
    violations := cis.violations_vm_backup with input as {
        "tags": {"Environment": "production"},
        "backup": null
    }
    
    violations[_] == "Production VM lacks backup configuration"
}

test_backup_retention_period if {
    violations := cis.violations_vm_backup with input as {
        "tags": {"Environment": "production"},
        "backup": {
            "policy_id": "backup-123",
            "retention_days": 3
        }
    }
    
    violations[_] == "Backup retention 3 days is below minimum 7 days"
}

#-----------------------------------------------------------------------------
# Test: VM Resource Optimization
#-----------------------------------------------------------------------------

test_resource_deprecated_instance_type if {
    violations := cis.violations_vm_resources with input as {
        "platform": "aws_ec2",
        "instance_type": "m3.large"
    }
    
    violations[_] == "VM using deprecated instance type 'm3.large'"
}

test_resource_termination_protection if {
    violations := cis.violations_vm_resources with input as {
        "platform": "aws_ec2",
        "tags": {"env": "prod"},
        "disable_api_termination": false
    }
    
    violations[_] == "Production VM should have termination protection enabled"
}

test_resource_stopped_instance_cost if {
    violations := cis.violations_vm_resources with input as {
        "platform": "aws_ec2",
        "state": "stopped",
        "public_ip_address": "1.2.3.4",
        "stop_time_ns": time.now_ns() - (8 * 24 * 60 * 60 * 1000000000)  # 8 days ago
    }
    
    violations[_] == "Stopped instance with public IP incurring charges"
}

#-----------------------------------------------------------------------------
# Test: Helper Functions
#-----------------------------------------------------------------------------

test_has_public_ip_aws if {
    result := cis.has_public_ip with input as {
        "platform": "aws_ec2",
        "public_ip_address": "54.1.2.3"
    }
    
    result == true
}

test_has_public_ip_azure if {
    result := cis.has_public_ip with input as {
        "platform": "azure_vm",
        "network_profile": {
            "network_interfaces": [{
                "ip_configurations": [{
                    "public_ip_address": {"id": "/subscriptions/.../publicIP1"}
                }]
            }]
        }
    }
    
    result == true
}

test_has_public_ip_gcp if {
    result := cis.has_public_ip with input as {
        "platform": "gcp_compute",
        "network_interfaces": [{
            "access_configs": [{
                "nat_ip": "35.1.2.3"
            }]
        }]
    }
    
    result == true
}

test_is_production_vm if {
    result1 := cis.is_production_vm with input.tags as {"Environment": "Production"}
    result2 := cis.is_production_vm with input.tags as {"env": "prod"}
    result3 := cis.is_production_vm with input.tags as {"env": "dev"}
    
    result1 == true
    result2 == true
    result3 == false
}

test_is_sensitive_port if {
    ssh := cis.is_sensitive_port(22)
    rdp := cis.is_sensitive_port(3389)
    mysql := cis.is_sensitive_port(3306)
    custom := cis.is_sensitive_port(8080)
    
    ssh == true
    rdp == true
    mysql == true
    custom == false
}

#-----------------------------------------------------------------------------
# Test: Compliance Summary
#-----------------------------------------------------------------------------

test_compliance_summary_structure if {
    summary := cis.compliance_summary with input as {
        "resource_type": "instance",
        "instance_id": "i-12345",
        "name": "web-server-01",
        "platform": "aws_ec2",
        "block_device_mappings": [{
            "device_name": "/dev/sda1",
            "ebs": {"encrypted": false}
        }]
    }
    
    # Verify structure
    summary.resource.type == "instance"
    summary.resource.id == "i-12345"
    summary.resource.platform == "aws_ec2"
    is_boolean(summary.compliant)
    is_object(summary.violations)
    count(summary.violations.critical) > 0
}

#-----------------------------------------------------------------------------
# Test: Enforcement Decision
#-----------------------------------------------------------------------------

test_enforcement_allow_with_medium_violations if {
    decision := cis.decision with input as {
        "resource_type": "vm",
        "platform": "aws_ec2",
        "instance_id": "i-12345",
        "block_device_mappings": [{
            "device_name": "/dev/sda1",
            "ebs": {"encrypted": true}
        }],
        "iam_instance_profile": {"arn": "arn:aws:iam::123456789012:instance-profile/role"},
        "monitoring": {"state": "disabled"},  # Medium severity
        "tags": {}
    }
    
    # Should allow - only medium violations
    decision.allow == true
    count(decision.violations.medium) > 0
}

test_enforcement_deny_with_critical_violations if {
    decision := cis.decision with input as {
        "resource_type": "vm",
        "platform": "aws_ec2",
        "instance_id": "i-12345",
        "block_device_mappings": [{
            "device_name": "/dev/sda1",
            "ebs": {"encrypted": false}  # Critical violation
        }]
    }
    
    decision.allow == false
    "enable_disk_encryption" in decision.required_actions
}

#-----------------------------------------------------------------------------
# Test: Cross-Platform Compatibility
#-----------------------------------------------------------------------------

test_cross_platform_gcp if {
    summary := cis.compliance_summary with input as {
        "resource_type": "instance",
        "platform": "gcp_compute",
        "instance_id": "instance-1",
        "name": "web-server",
        "disks": [{
            "device_name": "boot-disk",
            "disk_encryption_key": null
        }],
        "metadata": {"items": []},
        "network_interfaces": []
    }
    
    count(summary.violations.critical) > 0  # Missing encryption
    summary.resource.platform == "gcp_compute"
}
