# Deterministic kind fixtures

These keys and discovery documents exist only for end-to-end tests. They are
not interoperability vectors and must never be used for an identity outside
this repository.

`agent-a` is the initial signing key. `agent-b` replaces it in rotation
scenarios. The fixture-only resolver starts in `healthy_v1` and exposes these
test-only modes over its Unix socket:

```text
healthy-v1  initial JWKS
rotated-v2  replacement JWKS with agent-b only
malformed   syntactically invalid discovery response
unavailable transport failure
delayed     response slower than the resolver deadline
```

The production resolver binary does not contain the fixture transport or the
`serve-fixtures` / `fixture-control` commands. Build the fixture image with:

```sh
make kind-fixture-up
```

The signed-request generator is available as `wba-kind-request`. The complete
Rust suite runs against a persistent cluster:

```sh
make kind-test
```

The suite leaves the cluster and generated resources in place. Inspect them
with `make kind-status` and `make kind-logs`, or keep a manual gateway forward
open with `make kind-forward`. Select a manual mode with `make kind-apply
MODE=required`. Remove the cluster with `make kind-down`.

Kind does not provide an external LoadBalancer address. The Gateway can show
`AddressNotAssigned` while its listener and data plane are healthy. Tests use
`kubectl port-forward` instead of relying on that address.

The standard suite requires Docker access, kind, kubectl, and permission to bind
a local port for kubectl port-forward. It tests observe, optional, and required
modes, fixture failures, signed requests, forged headers, key rotation, sidecar
restart recovery, and Envoy Gateway composition. Portability is a separate
optional test because it needs a second Kubernetes node image and a module
installer image.

The Envoy Gateway composition tests are separate because they install policies
and Redis. Use `make kind-composition-test` for SecurityPolicy, per proxy local
limits, and global identity limits across two proxy pods. Local limits do not
support distinct header matching. Use
`make kind-portability-test` for the init container module loader. The default
image volume path targets Kubernetes 1.35 or newer. The fallback overlay targets
Kubernetes 1.34.
