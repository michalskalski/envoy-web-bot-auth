# Envoy Web Bot Auth

Envoy Web Bot Auth is an Envoy Dynamic Module and local resolver for the
[Web Bot Auth Protocol 02](https://datatracker.ietf.org/doc/html/draft-meunier-webbotauth-httpsig-protocol-02).
It verifies signed automated requests at the gateway, resolves public
verification keys, and makes a trusted caller identity available to later Envoy
policy.

Use it when an origin needs to identify an automated caller before applying its
own access policy. A verified identity is an authentication input. It does not
grant authorization, express reputation, or provide replay protection.

See [the architecture](docs/architecture.md) for the supported protocol profile,
resolver design, limits, egress model, and protocol update policy. See
[deployment](docs/deployment.md) and [configuration](docs/configuration.md) for
operator setup.

## Admission modes

| Result | `observe` | `optional` | `required` |
|---|---:|---:|---:|
| No signature | allow | allow | 403 with `Accept-Signature` |
| Malformed fields | allow | 400 | 400 |
| Rejected or unsupported credential | allow | 403 | 403 |
| Resolver unavailable | allow | 503 | 503 |
| Verified | allow | allow | allow |

After verification, the module enriches the request with trusted authentication
data for later Envoy filters and upstream services. Use that data for your own
authorization and rate policy. See [trusted outputs](docs/configuration.md#trusted-outputs)
for the headers and dynamic metadata.

## Deployment

Kubernetes is the primary deployment. Envoy and the resolver sidecar communicate
through `/run/wba/resolver.sock` on a shared `emptyDir`. The supplied manifests
run the resolver as UID and GID 65532 and use an Envoy pipe cluster.

Standalone development can use loopback TCP:

```text
web-bot-auth-resolver serve \
  --listen=tcp://127.0.0.1:8081 \
  --egress-mode=direct
```

The resolver supports `direct` and `proxy` egress. Direct mode validates DNS
answers and pins the selected address. Proxy mode requires a trusted proxy to
enforce final destination policy. Details are in [the architecture](docs/architecture.md#egress).

## Try and verify

Use the persistent local Kubernetes environment:

```text
make kind-up
make kind-apply MODE=required
make kind-test
```

Run the local and release gates with:

```text
make test
make integration-test
make transport-test
make manifest-check
make release-verify
```

`nix develop` provides the required client tools. Docker access is still a host
requirement. [CONTRIBUTING.md](CONTRIBUTING.md) describes the contributor and
release workflow.
