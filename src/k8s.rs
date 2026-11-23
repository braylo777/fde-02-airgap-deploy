//! Air-gap lint for rendered Kubernetes manifests (JSON objects).

use crate::{finding, list, strs, summarize};
use serde_json::Value;

/// Split an image ref into (registry host, has digest).
pub fn image_registry(image: &str) -> (String, bool) {
    let digest = image.contains("@sha256:");
    let first = image.split('/').next().unwrap_or("");
    // A first path part with a dot or colon, or "localhost", is a registry host.
    let host = if image.contains('/')
        && (first.contains('.') || first.contains(':') || first == "localhost")
    {
        first.to_string()
    } else {
        "docker.io".to_string() // implicit Docker Hub
    };
    (host, digest)
}

fn name_of(o: &Value) -> String {
    format!(
        "{}/{}",
        o["kind"].as_str().unwrap_or("?"),
        o["metadata"]["name"].as_str().unwrap_or("?")
    )
}

fn pod_spec(o: &Value) -> Option<&Value> {
    match o["kind"].as_str()? {
        "Pod" => Some(&o["spec"]),
        "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "ReplicaSet" => {
            Some(&o["spec"]["template"]["spec"])
        }
        "CronJob" => Some(&o["spec"]["jobTemplate"]["spec"]["template"]["spec"]),
        _ => None,
    }
}

pub fn lint(objects: &[Value], registries: &[String]) -> Vec<Value> {
    let mut f = Vec::new();
    let mut has_default_deny = false;
    for o in objects {
        let n = name_of(o);
        if o["kind"] == "NetworkPolicy" {
            let spec = &o["spec"];
            let empty_selector = spec["podSelector"]
                .as_object()
                .map(|m| m.is_empty())
                .unwrap_or(false);
            let types = strs(&spec["policyTypes"]);
            let no_egress_rules = spec["egress"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true);
            if empty_selector
                && types.iter().any(|t| t == "Egress")
                && types.iter().any(|t| t == "Ingress")
                && no_egress_rules
            {
                has_default_deny = true;
            }
            for rule in spec["egress"].as_array().into_iter().flatten() {
                for to in rule["to"].as_array().into_iter().flatten() {
                    if to["ipBlock"]["cidr"] == "0.0.0.0/0" || to["ipBlock"]["cidr"] == "::/0" {
                        f.push(finding(
                            "high",
                            "no-open-egress",
                            &n,
                            "egress to 0.0.0.0/0 leaves the VPC".into(),
                        ));
                    }
                }
                if rule.get("to").is_none() {
                    f.push(finding(
                        "high",
                        "no-open-egress",
                        &n,
                        "egress rule without `to` allows any destination".into(),
                    ));
                }
            }
        }
        if o["kind"] == "Service" && o["spec"]["type"] == "LoadBalancer" {
            let ann = &o["metadata"]["annotations"];
            let internal = ann["service.beta.kubernetes.io/aws-load-balancer-internal"] == "true"
                || ann["service.beta.kubernetes.io/aws-load-balancer-scheme"] == "internal"
                || ann["networking.gke.io/load-balancer-type"] == "Internal"
                || ann["service.beta.kubernetes.io/azure-load-balancer-internal"] == "true";
            if !internal {
                f.push(finding(
                    "high",
                    "internal-lb-only",
                    &n,
                    "LoadBalancer without an internal annotation gets a public IP".into(),
                ));
            }
        }
        let Some(spec) = pod_spec(o) else { continue };
        if spec["hostNetwork"] == true {
            f.push(finding(
                "high",
                "no-host-network",
                &n,
                "hostNetwork bypasses NetworkPolicy".into(),
            ));
        }
        if spec["automountServiceAccountToken"] != false {
            f.push(finding(
                "medium",
                "no-sa-token",
                &n,
                "set automountServiceAccountToken: false unless the pod calls the API".into(),
            ));
        }
        let containers = spec["containers"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(spec["initContainers"].as_array().into_iter().flatten());
        for c in containers {
            let cn = format!("{n}:{}", c["name"].as_str().unwrap_or("?"));
            let image = c["image"].as_str().unwrap_or("");
            let (host, digest) = image_registry(image);
            if !registries.iter().any(|r| r == &host) {
                f.push(finding(
                    "high",
                    "internal-registry",
                    &cn,
                    format!("image `{image}` pulls from {host}, not an internal registry"),
                ));
            }
            if !digest {
                f.push(finding(
                    "high",
                    "pin-digest",
                    &cn,
                    format!("image `{image}` is not pinned by @sha256 digest"),
                ));
            }
            let sc = &c["securityContext"];
            if sc["privileged"] == true {
                f.push(finding(
                    "high",
                    "no-privileged",
                    &cn,
                    "privileged container".into(),
                ));
            }
            if sc["runAsNonRoot"] != true && spec["securityContext"]["runAsNonRoot"] != true {
                f.push(finding(
                    "medium",
                    "run-as-non-root",
                    &cn,
                    "runAsNonRoot is not set".into(),
                ));
            }
            if sc["readOnlyRootFilesystem"] != true {
                f.push(finding(
                    "medium",
                    "read-only-root",
                    &cn,
                    "readOnlyRootFilesystem is not set".into(),
                ));
            }
            let req_gpu = &c["resources"]["requests"]["nvidia.com/gpu"];
            let lim_gpu = &c["resources"]["limits"]["nvidia.com/gpu"];
            if !req_gpu.is_null() && lim_gpu.is_null() {
                f.push(finding(
                    "high",
                    "gpu-limits",
                    &cn,
                    "GPU requested without a limit; the device plugin needs limits".into(),
                ));
            }
            if !lim_gpu.is_null() && spec["nodeSelector"].is_null() && spec["affinity"].is_null() {
                f.push(finding(
                    "medium",
                    "gpu-node-pool",
                    &cn,
                    "GPU pod has no nodeSelector/affinity for the GPU pool".into(),
                ));
            }
        }
    }
    if !has_default_deny {
        f.push(finding(
            "high",
            "default-deny",
            "namespace",
            "no default-deny NetworkPolicy (empty podSelector, Ingress+Egress, no egress rules)"
                .into(),
        ));
    }
    f
}

pub fn lint_op(i: &Value) -> Result<Value, String> {
    let registries = strs(&i["internal_registries"]);
    if registries.is_empty() {
        return Err("`internal_registries` must list at least one registry host".into());
    }
    Ok(summarize(lint(list(i, "manifests")?, &registries)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn deny() -> Value {
        json!({"kind": "NetworkPolicy", "metadata": {"name": "default-deny"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}})
    }
    fn good_deploy() -> Value {
        json!({"kind": "Deployment", "metadata": {"name": "vllm"}, "spec": {"template": {"spec": {
            "automountServiceAccountToken": false, "nodeSelector": {"pool": "gpu"},
            "securityContext": {"runAsNonRoot": true},
            "containers": [{"name": "srv", "image": "registry.corp.internal/vllm/vllm-openai@sha256:abcd",
                "securityContext": {"readOnlyRootFilesystem": true},
                "resources": {"limits": {"nvidia.com/gpu": 1}}}]}}}})
    }
    fn regs() -> Vec<String> {
        vec!["registry.corp.internal".into()]
    }

    #[test]
    fn registry_parsing() {
        assert_eq!(image_registry("nginx:1.25"), ("docker.io".into(), false));
        assert_eq!(
            image_registry("ghcr.io/a/b@sha256:00"),
            ("ghcr.io".into(), true)
        );
        assert_eq!(
            image_registry("localhost:5000/x"),
            ("localhost:5000".into(), false)
        );
        assert_eq!(image_registry("library/nginx"), ("docker.io".into(), false));
    }
    #[test]
    fn clean_bundle_passes() {
        assert!(lint(&[deny(), good_deploy()], &regs()).is_empty());
    }
    #[test]
    fn public_unpinned_image_fails() {
        let mut d = good_deploy();
        d["spec"]["template"]["spec"]["containers"][0]["image"] = json!("vllm/vllm-openai:latest");
        let f = lint(&[deny(), d], &regs());
        let rules: Vec<&str> = f.iter().map(|x| x["rule"].as_str().unwrap()).collect();
        assert!(rules.contains(&"internal-registry") && rules.contains(&"pin-digest"));
    }
    #[test]
    fn missing_default_deny_fails() {
        let f = lint(&[good_deploy()], &regs());
        assert_eq!(f[0]["rule"], "default-deny");
    }
    #[test]
    fn open_egress_and_public_lb_fail() {
        let np = json!({"kind": "NetworkPolicy", "metadata": {"name": "allow-all"},
            "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]}});
        let svc = json!({"kind": "Service", "metadata": {"name": "api"}, "spec": {"type": "LoadBalancer"}});
        let f = lint(&[deny(), np, svc], &regs());
        assert_eq!(f.iter().filter(|x| x["severity"] == "high").count(), 2);
    }
    #[test]
    fn gpu_request_without_limit() {
        let mut d = good_deploy();
        d["spec"]["template"]["spec"]["containers"][0]["resources"] =
            json!({"requests": {"nvidia.com/gpu": 1}});
        assert!(lint(&[deny(), d], &regs())
            .iter()
            .any(|x| x["rule"] == "gpu-limits"));
    }
}
