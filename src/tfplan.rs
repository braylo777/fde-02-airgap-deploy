//! Scan a Terraform JSON plan (`terraform show -json plan.out`) for isolation breaks.
//! Reads `resource_changes[].change.after`, so it checks what *will* exist after apply.

use crate::{finding, list, summarize};
use serde_json::Value;

fn open_cidr(v: &Value) -> bool {
    v.as_array()
        .map(|a| a.iter().any(|x| x == "0.0.0.0/0" || x == "::/0"))
        .unwrap_or(false)
}

pub fn scan(changes: &[Value]) -> Vec<Value> {
    let mut f = Vec::new();
    for rc in changes {
        let actions = rc["change"]["actions"].as_array();
        if actions
            .map(|a| a.len() == 1 && a[0] == "delete")
            .unwrap_or(false)
        {
            continue;
        }
        let addr = rc["address"].as_str().unwrap_or("?");
        let a = &rc["change"]["after"];
        match rc["type"].as_str().unwrap_or("") {
            "aws_internet_gateway" => f.push(finding(
                "high",
                "no-igw",
                addr,
                "internet gateway in an air-gapped VPC".into(),
            )),
            "aws_nat_gateway" => f.push(finding(
                "high",
                "no-nat",
                addr,
                "NAT gateway gives private subnets internet egress".into(),
            )),
            "aws_subnet" if a["map_public_ip_on_launch"] == true => f.push(finding(
                "high",
                "no-public-ip",
                addr,
                "subnet assigns public IPs on launch".into(),
            )),
            "aws_instance" if a["associate_public_ip_address"] == true => f.push(finding(
                "high",
                "no-public-ip",
                addr,
                "instance gets a public IP".into(),
            )),
            "aws_security_group" => {
                for e in a["egress"].as_array().into_iter().flatten() {
                    if open_cidr(&e["cidr_blocks"]) || open_cidr(&e["ipv6_cidr_blocks"]) {
                        f.push(finding(
                            "high",
                            "no-open-egress",
                            addr,
                            "security group egress to 0.0.0.0/0".into(),
                        ));
                    }
                }
                for e in a["ingress"].as_array().into_iter().flatten() {
                    if open_cidr(&e["cidr_blocks"]) {
                        f.push(finding(
                            "high",
                            "no-open-ingress",
                            addr,
                            "security group ingress from 0.0.0.0/0".into(),
                        ));
                    }
                }
            }
            "aws_vpc_security_group_egress_rule" if a["cidr_ipv4"] == "0.0.0.0/0" => {
                f.push(finding(
                    "high",
                    "no-open-egress",
                    addr,
                    "egress rule to 0.0.0.0/0".into(),
                ))
            }
            "aws_s3_bucket_public_access_block" => {
                for k in [
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                ] {
                    if a[k] != true {
                        f.push(finding(
                            "high",
                            "s3-block-public",
                            addr,
                            format!("{k} must be true"),
                        ));
                    }
                }
            }
            "aws_eks_cluster" if a["vpc_config"][0]["endpoint_public_access"] != false => {
                f.push(finding(
                    "high",
                    "private-eks-endpoint",
                    addr,
                    "EKS API endpoint is public".into(),
                ))
            }
            "aws_ecr_repository" if a["image_tag_mutability"] != "IMMUTABLE" => f.push(finding(
                "medium",
                "immutable-tags",
                addr,
                "ECR tags are mutable; set IMMUTABLE".into(),
            )),
            _ => {}
        }
    }
    f
}

pub fn scan_op(i: &Value) -> Result<Value, String> {
    let plan = i.get("plan").unwrap_or(i);
    Ok(summarize(scan(list(plan, "resource_changes")?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn rc(t: &str, after: Value) -> Value {
        json!({"address": format!("{t}.x"), "type": t, "change": {"actions": ["create"], "after": after}})
    }
    #[test]
    fn igw_and_open_sg_flagged() {
        let f = scan(&[
            rc("aws_internet_gateway", json!({})),
            rc(
                "aws_security_group",
                json!({"egress": [{"cidr_blocks": ["0.0.0.0/0"]}]}),
            ),
        ]);
        assert_eq!(f.len(), 2);
    }
    #[test]
    fn private_resources_pass() {
        let f = scan(&[
            rc("aws_subnet", json!({"map_public_ip_on_launch": false})),
            rc(
                "aws_security_group",
                json!({"egress": [{"cidr_blocks": ["10.0.0.0/16"]}]}),
            ),
            rc(
                "aws_eks_cluster",
                json!({"vpc_config": [{"endpoint_public_access": false}]}),
            ),
        ]);
        assert!(f.is_empty());
    }
    #[test]
    fn deletes_are_ignored() {
        let mut r = rc("aws_internet_gateway", json!(null));
        r["change"]["actions"] = json!(["delete"]);
        assert!(scan(&[r]).is_empty());
    }
}
