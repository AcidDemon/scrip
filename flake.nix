{
  description = "scrip - a self-hosted pastebin you drive from the shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = f: lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] f;
      cargoToml = lib.importTOML ./Cargo.toml;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = cargoToml.package.name;
            version = cargoToml.package.version;
            # Include only build inputs so documentation and CI edits do not
            # rebuild the crate. Add tests/ if doCheck is enabled.
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./src
                ./assets
              ];
            };
            cargoLock.lockFile = ./Cargo.lock;
            # CI runs `cargo test --locked` outside the Nix sandbox. The e2e
            # tests start a server and wait for its startup output, which
            # times out inside the build sandbox.
            doCheck = false;
            meta = {
              description = "Self-hosted pastebin: pipe anything into a TCP port, get a link back";
              license = lib.licenses.mit;
              mainProgram = "scrip";
            };
          };
        }
      );

      nixosModules.default =
        { pkgs, lib, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.scrip.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };

      # Eval-only smoke test: forcing the rendered units catches option typos
      # and type errors without building a whole NixOS system.
      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          eval = lib.nixosSystem {
            modules = [
              self.nixosModules.default
              {
                nixpkgs.hostPlatform = system;
                system.stateVersion = "25.11";
                services.scrip = {
                  enable = true;
                  openFirewall = true;
                  nftables.enable = true;
                  settings.base_url = "https://paste.example.com";
                };
              }
            ];
          };
        in
        {
          # Separate files let scripts/unit-drift.sh compare each unit with
          # its Debian counterpart.
          module = pkgs.linkFarm "scrip-module-check" [
            {
              name = "scrip.service";
              path = pkgs.writeText "scrip.service" eval.config.systemd.units."scrip.service".text;
            }
            {
              name = "scrip-firewall.service";
              path = pkgs.writeText "scrip-firewall.service" eval.config.systemd.units."scrip-firewall.service".text;
            }
            {
              name = "open-tcp-ports";
              path = pkgs.writeText "open-tcp-ports" (
                toString eval.config.networking.firewall.allowedTCPPorts
              );
            }
          ];
        }
      );
    };
}
