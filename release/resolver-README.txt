web-bot-auth-resolver

This archive contains the Web Bot Auth resolver sidecar. The default
deployment uses a Unix domain socket. Run the binary with serve to start the
resolver and use probe to check its socket.

The supported runtime, SDK revision, protocol profile, and build target are in
compatibility.json. The resolver is a static musl binary for the architecture
in the filename.
