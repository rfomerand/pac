# CIS Kubernetes Benchmark v1.8.0
# Organization: Example Corp Security Team
# Last Updated: 2025-01-20
# Policy Format: Open Policy Agent (OPA) Rego v0.60.0

package kubernetes.security.cis

import rego.v1

# Metadata for policy management and compliance tracking
metadata := {
    "version": "1.0.0",
    "framework": "CIS Kubernetes Benchmark",
    "severity_levels": {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4
    }
}

#-----------------------------------------------------------------------------
# Rule: pod_security_context_required
# CIS Control: 5.3.2 - Minimize the admission of containers with allowPrivilegeEscalation
# Description: Ensures pods have proper security context defined
#-----------------------------------------------------------------------------

default pod_security_context_required := false

pod_security_context_required if {
    input.kind == "Pod"
    count(violations_pod_security_context) == 0
}

violations_pod_security_context contains msg if {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
    msg := "Pod must set securityContext.runAsNonRoot to true"
}

violations_pod_security_context contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Container '%s' has allowPrivilegeEscalation set to true", [container.name])
}

violations_pod_security_context contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' is running in privileged mode", [container.name])
}

#-----------------------------------------------------------------------------
# Rule: network_policy_required
# CIS Control: 5.3.1 - Ensure that the CNI in use supports Network Policies
# Description: Validates that namespaces have network policies defined
#-----------------------------------------------------------------------------

default network_policy_required := false

network_policy_required if {
    input.kind == "Namespace"
    namespace_has_network_policy
}

namespace_has_network_policy if {
    count(data.kubernetes.networkpolicies[input.metadata.name]) > 0
}

network_policy_violations contains msg if {
    input.kind == "Namespace"
    not namespace_has_network_policy
    not is_system_namespace
    msg := sprintf("Namespace '%s' lacks network policies", [input.metadata.name])
}

#-----------------------------------------------------------------------------
# Rule: resource_limits_required  
# CIS Control: 5.3.5 - Ensure that containers have resource limits
# Description: Enforces resource limits on containers to prevent resource exhaustion
#-----------------------------------------------------------------------------

default resource_limits_required := false

resource_limits_required if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod"]
    count(violations_resource_limits) == 0
}

violations_resource_limits contains msg if {
    container := get_containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%s' missing memory limits", [container.name])
}

violations_resource_limits contains msg if {
    container := get_containers[_]
    not container.resources.limits.cpu
    msg := sprintf("Container '%s' missing CPU limits", [container.name])
}

violations_resource_limits contains msg if {
    container := get_containers[_]
    container.resources.requests.memory
    container.resources.limits.memory
    memory_ratio := to_number(container.resources.requests.memory) / to_number(container.resources.limits.memory)
    memory_ratio < 0.5
    msg := sprintf("Container '%s' has memory request/limit ratio below 50%%", [container.name])
}

#-----------------------------------------------------------------------------
# Rule: image_pull_policy_always
# CIS Control: 5.3.4 - Ensure that container images are scanned
# Description: Ensures latest images are pulled for better security scanning
#-----------------------------------------------------------------------------

default image_pull_policy_always := false

image_pull_policy_always if {
    count(violations_image_pull_policy) == 0
}

violations_image_pull_policy contains msg if {
    container := get_containers[_]
    not is_local_image(container.image)
    container.imagePullPolicy != "Always"
    msg := sprintf("Container '%s' should use imagePullPolicy: Always", [container.name])
}

#-----------------------------------------------------------------------------
# Rule: pod_disruption_budget_required
# Best Practice: Ensure high availability configurations
# Description: Validates PodDisruptionBudget exists for deployments
#-----------------------------------------------------------------------------

default pod_disruption_budget_required := false

pod_disruption_budget_required if {
    input.kind == "Deployment"
    input.spec.replicas > 1
    has_pod_disruption_budget
}

has_pod_disruption_budget if {
    selector := input.spec.selector.matchLabels
    pdb := data.kubernetes.poddisruptionbudgets[_]
    pdb.spec.selector.matchLabels == selector
}

#-----------------------------------------------------------------------------
# Helper Functions
#-----------------------------------------------------------------------------

# Extract containers from different workload types
get_containers[container] := container if {
    input.kind == "Pod"
    container := input.spec.containers[_]
}

get_containers[container] := container if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"]
    container := input.spec.template.spec.containers[_]
}

get_containers[container] := container if {
    input.kind == "CronJob"
    container := input.spec.jobTemplate.spec.template.spec.containers[_]
}

get_containers[container] := container if {
    input.kind == "Job"
    container := input.spec.template.spec.containers[_]
}

# Check if namespace is a system namespace
is_system_namespace if {
    input.metadata.name in [
        "kube-system",
        "kube-public", 
        "kube-node-lease",
        "gatekeeper-system"
    ]
}

# Check if image is from local registry
is_local_image(image) if {
    contains(image, "localhost:")
}

is_local_image(image) if {
    not contains(image, "/")
}

#-----------------------------------------------------------------------------
# Compliance Summary Rule
#-----------------------------------------------------------------------------

compliance_summary := summary if {
    critical_violations := [v | 
        v := violations_pod_security_context[_]
    ]
    
    high_violations := [v |
        v := violations_resource_limits[_]
    ]
    
    medium_violations := [v |
        v := violations_image_pull_policy[_]
    ]
    
    summary := {
        "compliant": count(critical_violations) + count(high_violations) + count(medium_violations) == 0,
        "violations": {
            "critical": critical_violations,
            "high": high_violations,
            "medium": medium_violations
        },
        "resource": {
            "kind": input.kind,
            "name": input.metadata.name,
            "namespace": input.metadata.namespace
        }
    }
}

#-----------------------------------------------------------------------------
# Enforcement Decision
#-----------------------------------------------------------------------------

# Main enforcement rule used by admission controllers
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
    "metadata": metadata
}
