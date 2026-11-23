//! Egress allow-list decisions. Deny by default; first matching rule wins.
//!
//! Rule forms: `{"cidr": "10.0.0.0/8", "ports": [443]}` or
//! `{"host": "*.s3.us-east-1.amazonaws.com", "ports": [443]}`. Empty `ports` = any port.

use crate::{field, list};
use serde_json::{json, Value};

pub fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut n = 0u32;
    for p in parts {
        if p.is_empty() || p.len() > 3 || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        n = (n << 8) | p.parse::<u8>().ok()? as u32;
    }
    Some(n)
}

pub fn cidr_contains(cidr: &str, ip: u32) -> Option<bool> {
    let (base, bits) = cidr.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Some(parse_ipv4(base)? & mask == ip & mask)
}

/// `*.example.com` matches `a.example.com` and `a.b.example.com`, not `example.com`.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let (p, h) = (
        pattern.to_ascii_lowercase(),
        host.to_ascii_lowercase().trim_end_matches('.').to_string(),
    );
    match p.strip_prefix("*.") {
        Some(suffix) => h.ends_with(&format!(".{suffix}")),
        None => p == h,
    }
}

pub fn decide(rules: &[Value], dest: &str, port: u64) -> (bool, Option<usize>) {
    let ip = parse_ipv4(dest);
    for (idx, r) in rules.iter().enumerate() {
        let ports = r["ports"].as_array();
        let port_ok = ports
            .map(|p| p.is_empty() || p.iter().any(|x| x.as_u64() == Some(port)))
            .unwrap_or(true);
        if !port_ok {
            continue;
        }
        let hit = match (r["cidr"].as_str(), r["host"].as_str(), ip) {
            (Some(c), _, Some(ip)) => cidr_contains(c, ip).unwrap_or(false),
            (_, Some(h), None) => host_matches(h, dest),
            _ => false,
        };
        if hit {
            return (r["action"] != "deny", Some(idx));
        }
    }
    (false, None)
}

pub fn check_op(i: &Value) -> Result<Value, String> {
    let rules = list(i, "rules")?;
    for r in rules {
        if r["cidr"] == "0.0.0.0/0" && r["action"] != "deny" {
            return Err("allow rule for 0.0.0.0/0 defeats the air gap; remove it".into());
        }
    }
    let mut out = Vec::new();
    for c in list(i, "connections")? {
        let dest = field(c, "dest")?.as_str().ok_or("dest must be a string")?;
        let port = c["port"].as_u64().unwrap_or(443);
        let (allowed, rule) = decide(rules, dest, port);
        out.push(json!({"dest": dest, "port": port, "allowed": allowed,
            "matched_rule": rule, "reason": if rule.is_none() { "no rule matched: default deny" } else { "rule matched" }}));
    }
    Ok(json!({"decisions": out}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv4_parse_strict() {
        assert_eq!(parse_ipv4("10.0.0.1"), Some(0x0a000001));
        assert_eq!(parse_ipv4("10.0.0.256"), None);
        assert_eq!(parse_ipv4("010.0.0.1"), None);
        assert_eq!(parse_ipv4("10.0.0"), None);
    }
    #[test]
    fn cidr() {
        let ip = parse_ipv4("10.20.30.40").unwrap();
        assert_eq!(cidr_contains("10.0.0.0/8", ip), Some(true));
        assert_eq!(cidr_contains("10.21.0.0/16", ip), Some(false));
        assert_eq!(cidr_contains("0.0.0.0/0", ip), Some(true));
        assert_eq!(cidr_contains("10.0.0.0/33", ip), None);
    }
    #[test]
    fn wildcard_hosts() {
        assert!(host_matches(
            "*.amazonaws.com",
            "s3.us-east-1.amazonaws.com"
        ));
        assert!(!host_matches("*.amazonaws.com", "amazonaws.com"));
        assert!(!host_matches("*.amazonaws.com", "evilamazonaws.com"));
        assert!(host_matches("api.corp", "API.corp."));
    }
    #[test]
    fn default_deny_and_ports() {
        let rules = vec![serde_json::json!({"cidr": "10.0.0.0/8", "ports": [443]})];
        assert_eq!(decide(&rules, "10.1.1.1", 443), (true, Some(0)));
        assert_eq!(decide(&rules, "10.1.1.1", 22), (false, None));
        assert_eq!(decide(&rules, "8.8.8.8", 443), (false, None));
    }
    #[test]
    fn open_rule_refused() {
        assert!(check_op(
            &serde_json::json!({"rules": [{"cidr": "0.0.0.0/0"}], "connections": []})
        )
        .is_err());
    }
}
