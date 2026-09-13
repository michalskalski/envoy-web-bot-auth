# Envoy Web Bot Auth

Envoy Web Bot Auth is an Envoy Dynamic Module and local resolver that uses
Ed25519 to implement a profile of the [Web Bot Auth HTTP Message Signatures
working group draft](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/).
The reviewed implementation baseline is
[`draft-ietf-webbotauth-httpsig-protocol-00`](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html).
It verifies signed automated requests at the gateway, resolves public
verification keys, and makes a trusted caller identity available to later Envoy
policy.

Use it when a target service needs to identify an automated caller before applying its
own access policy. A verified identity is an authentication input. It does not
grant authorization, express reputation, or provide replay protection.

See [the architecture](docs/architecture.md) for the supported protocol profile,
resolver design, limits, egress model, and protocol update policy. See
[operations](docs/operations.md) for deployment, configuration, and metrics.

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
authorization and rate policy. See [trusted outputs](docs/operations.md#trusted-outputs)
for the headers and dynamic metadata.

[CONTRIBUTING.md](CONTRIBUTING.md) describes the contributor and
release workflow.
