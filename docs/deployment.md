# Deployment

The Kubernetes files under `examples/kind` are working reference manifests.
They use local image names for Kind. Treat them as a template, not as a manifest
to apply unchanged to another cluster.

## Prerequisites

Use an Envoy Gateway and Envoy runtime combination recorded in
[`compatibility.toml`](../compatibility.toml). The normal deployment uses
Kubernetes image volumes. Kubernetes 1.34 uses the init container overlay.

## Official release images

After a GitHub Release is published, its three production OCI artifacts are
available from GitHub Container Registry. The release notes list their immutable
digests and build-provenance attestations:

```text
ghcr.io/michalskalski/envoy-web-bot-auth-module:v<VERSION>
ghcr.io/michalskalski/envoy-web-bot-auth-resolver:v<VERSION>
ghcr.io/michalskalski/envoy-web-bot-auth-module-installer:v<VERSION>
```

Use version tags to discover a release, then pin the digest listed in that
release in a production manifest. For example:

```text
ghcr.io/michalskalski/envoy-web-bot-auth-resolver@sha256:<DIGEST>
```

Before deployment, verify the resolver image's provenance attestation (replace
the placeholders with the digest from the release notes):

```sh
gh attestation verify \
  oci://ghcr.io/michalskalski/envoy-web-bot-auth-resolver@sha256:<DIGEST> \
  --repo michalskalski/envoy-web-bot-auth
```

The module image is an image-volume artifact, not a runnable container. The
module installer is needed only for the Kubernetes 1.34 fallback described
below. The deterministic Kind fixture resolver is never published.

## Build images locally

For development or a private registry, build the module and resolver images,
then tag and push them to a registry that your cluster can pull from:

```text
make image
docker tag envoy-web-bot-auth-module:dev registry.example/module:v0.1.0
docker tag envoy-web-bot-auth-resolver:dev registry.example/resolver:v0.1.0
docker push registry.example/module:v0.1.0
docker push registry.example/resolver:v0.1.0
```

Use immutable digests in a production manifest after verifying the release
artifacts.

## UDS sidecar layout

The deployment needs four pieces:

1. An image volume that contains `libenvoy_web_bot_auth.so`.
2. An `emptyDir` mounted at `/run/wba` in Envoy and the resolver.
3. A resolver sidecar that listens on `/run/wba/resolver.sock`.
4. A static Envoy pipe cluster that points at that socket.

The reference [EnvoyProxy](../examples/kind/resources.yaml) contains all four.
Replace the two image references and remove the Kind only `Never` pull policy.

The important parts look like this:

```yaml
spec:
  bootstrap:
    type: JSONPatch
    jsonPatches:
      - op: add
        path: /static_resources/clusters/-
        value:
          name: web-bot-auth-key-resolver
          connect_timeout: 2s
          type: STATIC
          load_assignment:
            cluster_name: web-bot-auth-key-resolver
            endpoints:
              - lb_endpoints:
                  - endpoint:
                      address:
                        pipe:
                          path: /run/wba/resolver.sock
  dynamicModules:
    - name: envoy-web-bot-auth
      source:
        type: Local
        local:
          path: /etc/envoy/dynamic-modules/libenvoy_web_bot_auth.so
```

The resolver runs as UID and GID 65532. Set pod `fsGroup: 65532` and use the
shared `emptyDir` so Envoy can connect to the socket.

## Attach the module

Attach an `EnvoyExtensionPolicy` to the routes that need Web Bot Auth:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: web-bot-auth
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: app
  dynamicModule:
    - name: envoy-web-bot-auth
      filterName: web-bot-auth
      config:
        mode: required
        resolver:
          cluster: web-bot-auth-key-resolver
          timeout_ms: 2000
```

Use `observe` first to inspect behavior without rejecting requests. Use
`optional` when unsigned requests are allowed but presented signatures must
verify. Use `required` when every request must verify.

Use [configuration.md](configuration.md) for all module and resolver settings.

## Kubernetes 1.34

Kubernetes 1.34 does not use the image volume path. Use
[the init container overlay](../examples/kind/overlays/init-container) and build
the local installer image with:

```text
make module-installer-image
```

Replace its image reference with an image in your registry before applying it.

## Standalone Envoy

[examples/standalone/envoy.yaml](../examples/standalone/envoy.yaml) is a loopback
TCP example. Start the resolver with:

```text
web-bot-auth-resolver serve \
  --listen=tcp://127.0.0.1:8081 \
  --egress-mode=direct
```

TCP listeners are restricted to loopback addresses. Use the UDS sidecar layout
for Kubernetes.
