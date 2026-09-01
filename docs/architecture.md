# Architecture

## Protocol profile

This project implements an Ed25519 focused profile of [Web Bot Auth Protocol
02](https://datatracker.ietf.org/doc/html/draft-meunier-webbotauth-httpsig-protocol-02).
The module accepts one signature and one identity per request. It supports `directory`,
`jwks_uri`, and `cimd` key discovery.

The default signature coverage requires `@authority` or `@target-uri` and the
`Signature-Agent` member named by the signed component key. Operators can require
additional supported components: `@method`, `@authority`, `@scheme`,
`@target-uri`, `@path`, `@query`, `signature`, `signature-input`, and
`signature-agent`.

The profile does not verify request bodies, arbitrary HTTP fields, multiple Web
Bot Auth signatures, algorithms other than Ed25519, redistributed key material,
or directory response signatures. Legacy item `Signature-Agent` support is opt
in.

The protocol is an active Internet Draft. This project does not change behavior
automatically when a new revision appears. Each revision requires a normative
review, fixtures, compatibility tests, and an explicit release decision. An RFC
is treated as a new target until it passes the same review.

Known RFC 9421 Ed25519 test keys are rejected unless `--allow-test-keys` is set
for development. Version 1 has no nonce store, so a valid signature can be
replayed until its expiry and covered request scope no longer permit it.

## Request flow

Envoy removes caller supplied assertion headers, parses the Web Bot Auth fields,
and sends one resolve request to the local resolver. The resolver returns either
a normalized identifier with an Ed25519 JWK or authoritative key absence. The
module recomputes the identifier and thumbprint and verifies the signature before
emitting trusted headers.

Resolver response errors, callout ID mismatch, identifier mismatch, thumbprint
mismatch, and unusable keys are unavailable results. They never create identity
metadata.

## Resolver and cache

The resolver has separate service, resource, fetch, cache, and limit layers.
Resources are cached by exact fetch URL and kind, not requested key ID. Query is
kept for fetches while normalized identities remove query and fragment. CIMD
metadata and its JWKS are separate resources. Resolution fetches at most one
metadata document and one JWKS document.

[Moka](https://docs.rs/moka/0.12/moka/) caches validated responses and ensures
that concurrent requests for the same resource share one refresh operation.
Standard HTTP caching rules determine when a cached response can be reused,
when to send a conditional request or revalidate it, and when serving a stale
response is allowed. A successful refresh replaces the whole resource. An
eligible transient refresh failure may serve the earlier representation within
its `stale-if-error` window; `must-revalidate` disables that fallback.

[Governor](https://docs.rs/governor/0.10/governor/) applies global, origin, and
resolved address rate limits. Tokio semaphores bound active handlers and outbound
fetches. Per resource circuits and refresh backoff reduce repeated failed work.
These controls are local to each resolver process and pod.

| Limit | Default |
|---|---:|
| Inbound JSON body | 8 KiB |
| Active handlers | 64 |
| Outbound fetches | 32 |
| Global fetch rate and burst | 16 and 32 per second |
| Per origin rate and burst | 2 and 4 per second |
| Per resolved address rate and burst | 8 and 16 per second |
| New origins | 256 per rolling minute |
| Cache, refresh, limiter, circuit entries | 1,024 each |
| Resolution deadline | 1,800 ms |
| Envoy callout timeout | 2,000 ms |

## Egress

Direct mode disables system proxy discovery, validates every DNS answer, rejects
unsafe or mixed answers, and pins the selected address for TLS. Redirects and
response decoding are disabled.

Proxy mode requires `HTTPS_PROXY`, ignores `NO_PROXY`, and has no direct fallback.
The proxy performs final hostname resolution and routing. It is therefore the
SSRF trust boundary and must enforce the required destination policy. The resolver
still validates the requested URL, port, and local DNS answers. It uses platform
trust roots and provides no custom CA setting.

HTTPS port 443 is allowed by default. Additional destination ports require
`--allowed-port`. Discovery responses require accepted JSON media types, identity
encoding, at most 64 KiB, and at most 32 keys.

## Transport and Kubernetes

The standalone resolver defaults to loopback TCP. The Kubernetes sidecar uses a
Unix socket. Socket mode is `0660`. Startup removes only a stale Unix
socket and rejects regular files and symlinks. SIGTERM removes the socket during
graceful shutdown.

The Kubernetes base uses a resolver sidecar, a shared `emptyDir`, UID and GID
65532, `fsGroup: 65532`, and an Envoy pipe cluster. The required overlay adds
readiness gating. Kubernetes 1.34 uses the init container compatibility path.

## Release artifacts

Release verification creates architecture specific module and resolver archives,
OCI archives, SBOMs, checksums, compatibility metadata, and a release manifest.
It checks archive contents, ELF architecture, module symbols, static resolver
linkage, and loading the module in the pinned Envoy runtime.
