{
  description = "Development shell for envoy-web-bot-auth";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      rustToolchain = pkgs.rust-bin.stable."1.97.1".default.override {
        extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
      };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          rustToolchain
          pkgs.llvmPackages.libclang
          pkgs.docker-client
          pkgs.docker-buildx
          pkgs.kind
          pkgs.kubernetes-helm
          pkgs.kubectl
          pkgs.syft
          pkgs.cargo-auditable
          pkgs.cargo-deny
          pkgs.skopeo
          pkgs.jq
          pkgs.ripgrep
          pkgs.actionlint
        ];

        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      };
    };
}
