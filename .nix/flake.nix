{
  description = "eal-api-server — development shell (toolchain + encrypted env files via sops/age/ores-sops)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    # The env-secret tooling is org-agnostic and lives in its own repo, so every
    # repo shares one implementation rather than a copied script.
    ores-sops.url = "github:ORESoftware/ores-sops";
  };

  outputs = { self, nixpkgs, flake-utils, ores-sops }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ ores-sops.overlays.default ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "eal-api-server";
          packages = with pkgs; [
            python3
            # Qualified deliberately: `with pkgs;` does not shadow the outputs
            # function's arguments, so a bare `ores-sops` would resolve to the
            # flake INPUT rather than the package.
            pkgs.ores-sops

            # encrypted env files — env/enc/*.env.enc, see env/README.md
            sops
            age
            just
            git
            direnv
          ];

          # Installs the merge/checkout refresh hooks and re-decrypts the active
          # environment. It deliberately does NOT pick an environment for you:
          # the first `just env-use <name>` stays explicit.
          shellHook = ores-sops.lib.shellHook + ''
            _repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
            if [ -L "$_repo_root/env" ] || [ -L "$_repo_root/env/dec" ]; then
              echo "env: refusing to prepare symlinked env/dec" >&2
              return 1 2>/dev/null || exit 1
            fi
            umask 077
            mkdir -p "$_repo_root/env/dec"
            chmod 700 "$_repo_root/env/dec"
            unset _repo_root
          '';
        };
      });
}
