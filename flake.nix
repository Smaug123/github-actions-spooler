{
  description = "GitHub webhook spooler: verifies HMAC and enqueues jobs to a maildir-style on-disk queue.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    let
      inherit (nixpkgs) lib;

      mkPkgs = system: import nixpkgs { inherit system; };

      mkSource = pkgs:
        let
          sourceRoot = toString ./.;
        in
        pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let
              rel = lib.removePrefix "${sourceRoot}/" (toString path);
            in
            rel == "Cargo.lock"
            || rel == "Cargo.toml"
            || rel == "src"
            || lib.hasPrefix "src/" rel
            || rel == "tests"
            || lib.hasPrefix "tests/" rel;
        };

      # Only evaluate the package derivation if Cargo.lock exists. Otherwise
      # the devshell would fail to evaluate on first use, before we've had a
      # chance to generate the lockfile.
      hasLockfile = builtins.pathExists ./Cargo.lock;

      mkSpool = pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "gh-webhook-spool";
          version = "0.1.0";
          src = mkSource pkgs;
          cargoLock.lockFile = ./Cargo.lock;
          meta = {
            description = "Tiny HMAC-verifying GitHub webhook spooler.";
            mainProgram = "gh-webhook-spool";
          };
        };
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = mkPkgs system;
      in
      {
        packages = lib.optionalAttrs hasLockfile (
          let spool = mkSpool pkgs; in {
            default = spool;
            gh-webhook-spool = spool;
          }
        );

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.git
            pkgs.pkg-config
          ];
        };
      });
}
