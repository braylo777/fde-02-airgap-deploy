# fde-02-airgap-deploy

**Forward Deployed Engineering — Stage 2 of 12: Air-Gapped & VPC Inference Deployments**

Policy checks that keep an LLM deployment inside a private VPC: internal digest-pinned images, default-deny networking, no public egress, no public IPs.

**Also built as Project 2 of 12, "One-Click Air-Gapped Helm Deployer",** from the companion [12 FDE projects post](https://x.com/suraj_sharma14/status/2125197762752806998).

**Live demo:** https://fde-02-airgap-deploy.braylo777.workers.dev — the Rust core runs in your browser as WebAssembly. No server, no tracking.

## Why this matters

Banks, hospitals and government buyers will not send data to a public API. The model has to run inside their VPC or on a network with no internet at all. The hard part is not starting the container; it is proving to their security team that nothing can leak out. This repo turns that proof into checks that run before every deploy: the same rules on the Kubernetes manifests, the Terraform plan and the egress firewall.

## What it does

- Kubernetes lint: internal registry, @sha256 pinning, default-deny NetworkPolicy, no 0.0.0.0/0 egress, internal-only load balancers, hardened pods, GPU limits and node pools
- Egress allow-list engine: strict IPv4/CIDR math, wildcard host rules, deny by default, refuses an allow-all rule
- Terraform plan scan: IGW, NAT, public IPs, open security groups, S3 public access, public EKS endpoint, mutable ECR tags
- Image mirror plan: skopeo commands that copy public images into the internal registry by digest
- Reference Terraform module (private VPC + VPC endpoints) and a Helm chart for the full private stack in infra/: offline vLLM server, Postgres with pgvector, Qdrant, all digest-pinned, default-deny with in-namespace-only egress

## What it does not do (yet)

- The Terraform and Helm in infra/ are reference code; they were not applied to a real AWS account from this repo
- No on-prem GPU provisioning (drivers, MIG, bare-metal) and no service mesh / mTLS zero-trust layer
- YAML input: render with helm template and convert to JSON first (helm template . | yq -o json); only IPv4 CIDRs

## Operations

Every operation takes JSON in and gives JSON out. The CLI, the tests and the demo page all use the same entry point.

| Operation | What it does |
|---|---|
| `lint_manifests` | A typical first draft: public image, tag not digest, no default-deny policy, GPU request without a limit, public load balancer. Every high finding blocks the deploy. |
| `check_egress` | Deny by default. Only the VPC range and the S3 endpoint on 443 are open. Try adding a rule with cidr 0.0.0.0/0: it is refused. |
| `scan_tf_plan` | Excerpt of terraform show -json. The plan adds an internet gateway, a public subnet, an open security group and a public EKS endpoint. |
| `mirror_plan` | Plan the copy of public images into the internal registry. Tag-only images are flagged: resolve the digest before the air gap. |

## Run it

You need Rust (stable). No Node, no npm.

```bash
git clone https://github.com/braylo777/fde-02-airgap-deploy
cd fde-02-airgap-deploy
cargo test
cargo run -- ops
```

Try the first demo example from the command line:

```bash
python3 -c 'import json;print(json.dumps(json.load(open("web/examples.json"))["ops"][0]["input"]))' | cargo run -q -- lint_manifests
```

## Reference infrastructure

`infra/terraform/main.tf` builds a VPC with private subnets only, no internet or NAT gateway, VPC endpoints for ECR, STS, CloudWatch Logs and S3, and an immutable ECR repository. `infra/helm/private-llm/` runs an OpenAI-compatible vLLM server with `HF_HUB_OFFLINE=1`, a default-deny NetworkPolicy, a read-only root filesystem and a GPU node selector.

Check them with this repo before you apply:

```bash
terraform plan -out plan.out && terraform show -json plan.out > plan.json
python3 -c 'import json;print(json.dumps({"plan":json.load(open("plan.json"))}))' | cargo run -q -- scan_tf_plan
```

## Build and deploy the demo

```bash
./build.sh    # tests, then compiles the core to web/app.wasm
./deploy.sh   # serves web/ as a Cloudflare Workers static-assets site (needs a Cloudflare login)
```

`web/` is a plain static site (`index.html`, `app.js`, `app.wasm`). It has no build step, so any static host works.

## Layout

```
src/lib.rs        operation list and router
src/api.rs        JSON entry point + the 3 WASM exports (alloc, dealloc, run)
src/main.rs       CLI
src/*.rs          one module per capability, each with unit tests
tests/            integration tests (every demo example must pass)
web/              demo page; examples.json drives both the page and this README
```

## Design choices

- **Rust, few dependencies.** Only `serde`, `serde_json`, `sha2` and `hmac`, pinned to exact versions with a committed `Cargo.lock`.
- **Deterministic.** Time, randomness and keys are inputs, so every result can be replayed in a test or an audit.
- **Fail closed.** Unknown input, missing fields or an unmatched policy gives an error or a denial, never a silent pass.

## Part of a series

This is one of 12 repos that work through a public Forward Deployed Engineering roadmap ([12 stages](https://x.com/suraj_sharma14/status/2124827808535048566), [12 projects](https://x.com/suraj_sharma14/status/2125197762752806998)). All 12: [github.com/braylo777?q=fde-](https://github.com/braylo777?tab=repositories&q=fde-).

## License

MIT — see [LICENSE](LICENSE). Built by [Braylo SI](https://braylo.si).
