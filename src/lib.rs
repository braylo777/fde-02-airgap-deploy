//! Stage 2 — Air-Gapped & VPC Inference Deployments.
//!
//! * `k8s`    — lint rendered Kubernetes manifests (e.g. `helm template … | yq -o json`)
//!   against air-gap rules: internal registry, digest-pinned images, default-deny
//!   NetworkPolicy, no 0.0.0.0/0 egress, hardened pods, GPU limits, internal load balancers.
//! * `egress` — decide if one outbound connection is allowed by an egress allow-list
//!   (CIDR and wildcard-domain rules, deny by default).
//! * `tfplan` — scan `terraform show -json plan.out` for resources that break isolation.
//! * `mirror` — plan the copy of public images into an internal registry, pinned by digest.

mod api;
pub mod egress;
pub mod k8s;
pub mod mirror;
pub mod tfplan;

pub use api::dispatch;
use serde_json::{json, Value};

pub const OPS: &[&str] = &["lint_manifests", "check_egress", "scan_tf_plan", "mirror_plan"];

pub(crate) fn field<'a>(v: &'a Value, k: &str) -> Result<&'a Value, String> {
    v.get(k).ok_or_else(|| format!("missing field `{k}`"))
}
pub(crate) fn list<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>, String> {
    field(v, k)?.as_array().ok_or_else(|| format!("`{k}` must be a list"))
}
pub(crate) fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// One finding. `severity` is "high" (blocks the deploy) or "medium" (warn).
pub(crate) fn finding(sev: &str, rule: &str, object: &str, msg: String) -> Value {
    json!({"severity": sev, "rule": rule, "object": object, "message": msg})
}

pub(crate) fn summarize(findings: Vec<Value>) -> Value {
    let high = findings.iter().filter(|f| f["severity"] == "high").count();
    json!({"pass": high == 0, "high": high, "medium": findings.len() - high, "findings": findings})
}

pub fn handle(op: &str, input: &Value) -> Result<Value, String> {
    match op {
        "lint_manifests" => k8s::lint_op(input),
        "check_egress" => egress::check_op(input),
        "scan_tf_plan" => tfplan::scan_op(input),
        "mirror_plan" => mirror::plan_op(input),
        _ => Err(format!("unknown op `{op}`; known: {}", OPS.join(", "))),
    }
}
