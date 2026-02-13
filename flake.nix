{
  description = "ERC-8004 Trustless Agents Rust SDK and MCP Server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, crane, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Extract version from workspace Cargo.toml
        workspaceCargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        version = workspaceCargoToml.workspace.package.version;

        # Use Rust version from rust-toolchain.toml
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common source filtering
        src = craneLib.cleanCargoSource ./.;

        # Common build inputs (runtime dependencies)
        commonBuildInputs = with pkgs; [ openssl ]
          ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration
          ];

        # Common native build inputs (build-time tools)
        commonNativeBuildInputs = with pkgs; [ pkg-config ];

        # Common arguments for all builds
        commonArgs = {
          inherit src;
          pname = "erc8004";
          inherit version;
          buildInputs = commonBuildInputs;
          nativeBuildInputs = commonNativeBuildInputs;
        };

        # Build dependencies separately for caching
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # The SDK library
        erc8004 = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "--package erc8004";
          meta = with pkgs.lib; {
            description = "ERC-8004 Trustless Agents Rust SDK";
            homepage = "https://github.com/ecdobry/erc8004";
            license = with licenses; [ mit asl20 ];
            maintainers = [
              {
                name = "Evan Dobry";
                email = "evandobry@gmail.com";
                github = "ecdobry";
                githubId = 16653165;
              }
            ];
          };
        });

        # The MCP server binary
        erc8004-mcp = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "--package erc8004-mcp";
          meta = with pkgs.lib; {
            description = "MCP server exposing the ERC-8004 SDK as tools";
            homepage = "https://github.com/ecdobry/erc8004";
            license = with licenses; [ mit asl20 ];
            maintainers = [
              {
                name = "Evan Dobry";
                email = "evandobry@gmail.com";
                github = "ecdobry";
                githubId = 16653165;
              }
            ];
          };
        });

      in
      {
        # `nix flake check` runs all of these
        checks = {
          inherit erc8004 erc8004-mcp;

          fmt = craneLib.cargoFmt { inherit src; };

          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- -D warnings";
          });

          tests = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
          });
        };

        packages = {
          inherit erc8004 erc8004-mcp;
          default = erc8004-mcp;
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages = with pkgs; [
            cargo-watch
            cargo-edit
            cargo-outdated
            cargo-audit
            cargo-expand
          ];

          # Environment variables
          RUST_BACKTRACE = "1";
        };

        # Formatter
        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
