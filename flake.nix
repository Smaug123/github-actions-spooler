{
  description = "GitHub webhook spooler: verifies HMAC and enqueues jobs to a maildir-style on-disk queue.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, crane, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = (import nixpkgs { inherit system; }).extend (import rust-overlay);

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;
          pname = "gh-webhook-spool";
          version = "0.1.0";
        };

        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          cargoExtraArgs = "--locked";
        });

        gh-webhook-spool = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "--locked";
          meta = {
            description = "Tiny HMAC-verifying GitHub webhook spooler.";
            mainProgram = "gh-webhook-spool";
          };
        });
      in
      {
        packages = {
          default = gh-webhook-spool;
          gh-webhook-spool = gh-webhook-spool;
        };

        devShells.default = craneLib.devShell {
          packages = [
            pkgs.git
          ];
        };
      });
}
