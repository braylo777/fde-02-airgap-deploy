//! Plan the mirror of public images into an internal registry for an air-gapped install.
//!
//! Output per image: the internal ref and a `skopeo copy` command. Images without a digest
//! are flagged: resolve the digest on the connected side first (`skopeo inspect`), then
//! mirror by digest so the air-gapped side can verify exactly what it runs.

use crate::{field, strs};
use serde_json::{json, Value};

/// Normalize to (registry, repository path, tag or digest suffix).
pub fn split(image: &str) -> (String, String, String) {
    let (name, suffix) = if let Some(at) = image.find('@') {
        (&image[..at], image[at..].to_string())
    } else {
        let last_slash = image.rfind('/').map(|i| i + 1).unwrap_or(0);
        match image[last_slash..].rfind(':') {
            Some(c) => (
                &image[..last_slash + c],
                image[last_slash + c..].to_string(),
            ),
            None => (image, ":latest".to_string()),
        }
    };
    let first = name.split('/').next().unwrap_or("");
    let explicit =
        name.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost");
    let (reg, repo) = if explicit {
        let (r, rest) = name.split_once('/').unwrap();
        (r.to_string(), rest.to_string())
    } else if name.contains('/') {
        ("docker.io".into(), name.to_string())
    } else {
        ("docker.io".into(), format!("library/{name}"))
    };
    (reg, repo, suffix)
}

pub fn plan_op(i: &Value) -> Result<Value, String> {
    let target = field(i, "internal_registry")?
        .as_str()
        .ok_or("internal_registry must be a string")?;
    let target = target.trim_end_matches('/');
    let mut items = Vec::new();
    let mut unpinned = 0;
    for img in strs(&i["images"]) {
        let (reg, repo, suffix) = split(&img);
        let pinned = suffix.starts_with("@sha256:");
        if !pinned {
            unpinned += 1;
        }
        let dest = format!("{target}/{reg}/{repo}{suffix}");
        items.push(json!({
            "source": format!("{reg}/{repo}{suffix}"),
            "internal_ref": dest,
            "pinned": pinned,
            "command": format!("skopeo copy --all --preserve-digests docker://{reg}/{repo}{suffix} docker://{dest}"),
            "note": if pinned { "ok" } else { "resolve digest first: skopeo inspect --format '{{.Digest}}'" }
        }));
    }
    Ok(json!({"images": items, "unpinned": unpinned, "ready_for_airgap": unpinned == 0}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn splits() {
        assert_eq!(
            split("nginx"),
            ("docker.io".into(), "library/nginx".into(), ":latest".into())
        );
        assert_eq!(
            split("vllm/vllm-openai:v0.9.0"),
            (
                "docker.io".into(),
                "vllm/vllm-openai".into(),
                ":v0.9.0".into()
            )
        );
        assert_eq!(
            split("nvcr.io/nvidia/tritonserver@sha256:ab"),
            (
                "nvcr.io".into(),
                "nvidia/tritonserver".into(),
                "@sha256:ab".into()
            )
        );
        assert_eq!(
            split("localhost:5000/x:1"),
            ("localhost:5000".into(), "x".into(), ":1".into())
        );
    }
    #[test]
    fn plan_flags_unpinned() {
        let r = plan_op(&serde_json::json!({"internal_registry": "reg.corp/", "images": ["nginx:1.27", "ghcr.io/a/b@sha256:00"]})).unwrap();
        assert_eq!(r["unpinned"], 1);
        assert_eq!(
            r["images"][1]["internal_ref"],
            "reg.corp/ghcr.io/a/b@sha256:00"
        );
    }
}
