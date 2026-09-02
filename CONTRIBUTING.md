# Contributing

Enter the reproducible shell with `nix develop`. Docker access remains a host
requirement because the shell supplies the client but does not run a daemon.

Run `make test` for formatting, unit tests, and Clippy. Run
`make integration-test` when changing resolver transport or fixture behavior.
Run `make transport-test` to execute the live TLS and CONNECT proxy checks.
Run `make manifest-check` after changing Kubernetes resources.

This is a virtual Cargo workspace. Code is split into
`crates/protocol` (wire types and URL identity rules), `crates/module` (Envoy
dynamic module), and `crates/resolver` (sidecar service). `tests/harness` owns
integration and kind only dependencies. The production resolver does not
compile fixture transports by default. Build a single publishable component
with `cargo build --release --locked -p PACKAGE`.

The kind suite is intentionally separate because it creates a persistent local
cluster. Use `make kind-test`, inspect failures with `make kind-status` and
`make kind-logs`, then remove the cluster with `make kind-down`.

Kind tests live in `tests/harness/tests/kind/e2e.rs`, with typed scenarios in
`scenario.rs` and behavior modules alongside it. Add a simple request
to the typed mode matrix. Use a separate named test for stateful behavior such
as rotation or a sidecar restart. Every admission case resets the fixture resolver
so cached data, retry state, and circuit state do not affect another case.

Envoy Gateway composition tests use isolated routes and policies. Keep
authentication before the Gateway SecurityPolicy through `EnvoyProxy.filterOrder`,
and match only the trusted status and identity headers. Local limits are per
proxy and do not support distinct header matching. Global limits use the
Gateway rate limit service and Redis for identity keys. The kind global limit
is configured fail open, so an unavailable rate limit service must not turn a
verified request into an outage. Run `make kind-composition-test` for these
checks.

The base module uses an image volume. Run `make kind-portability-test` with the
init container overlay to check the fallback used before Kubernetes 1.35. To
reproduce the Kubernetes 1.34 job locally, pass
`KIND_NODE_IMAGE=kindest/node:v1.34.0`. The version relationship is recorded in
`compatibility.toml`. This target builds the local `module-installer` image.
The release workflow also publishes a `module-installer.oci.tar` archive for
AMD64 and ARM64 images that can be imported into a registry.

## Upgrading Envoy compatibility

Each project release supports one tested Envoy version. Moving to a newer
version replaces the previously supported version. This project does not keep
branches for old Envoy versions or build a test matrix for multiple versions.

Choose a matching Envoy Gateway release, an exact Envoy runtime image and
digest, and the corresponding Envoy SDK revision. Update these coupled pins
together:

- `compatibility.toml`
- the SDK revision in `crates/module/Cargo.toml` and `Cargo.lock`
- the pinned runtime image in `Dockerfile` and `examples/kind/resources.yaml`
- `EG_VERSION` in `Makefile`

Run `cargo test -p web-bot-auth-test-harness --test compatibility`, `make
kind-test`, `make kind-portability-test`, and `make release-verify`. The
compatibility test catches inconsistent pins. The Kind and release gates test
the deployment and that the module loads in the pinned Envoy runtime. The
module release artifacts use the new Envoy version suffix, such as `envoy1.40`.

The resolver address ranges are pinned from the IANA special purpose
registries. When updating them, update the snapshot date and add boundary and
exception tests in the same change.

`make release-verify` builds `linux/amd64` (AMD64) and `linux/arm64` (ARM64)
release artifacts, emits Syft SPDX documents for each architecture for the
module, module installer, and resolver, checks embedded Cargo dependency data,
and records immutable digests. It needs Docker Buildx, Syft, Skopeo, and jq.
The Nix shell provides these tools.

Publishing the GitHub Release triggers a separate workflow that copies the
verified module, resolver, and module-installer OCI archives to GitHub Container
Registry and attaches build-provenance attestations.
