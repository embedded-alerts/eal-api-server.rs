# eal-api-server — task runner. Run `just` to see everything.
#
# Environment secrets live in env/enc/*.env.enc, encrypted with sops + age and
# committed to this repo. `just env-use <name>` decrypts to env/dec/<name>.env
# and points ./.env at it. See env/README.md for the workflow.

import '.just/env.just'

# Show available recipes.
default:
    @just --list

alias use := env-use
alias edit := env-edit
alias audit := env-check

# Activate <name>: decrypt it and point ./.env at env/dec/<name>.env.
# The link is relative and is only ever replaced when it already points into
# env/dec/ — an unmanaged .env file or foreign symlink is never clobbered.
[group('env')]
env-use name: (env-decrypt name)
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{ justfile_directory() }}"
    target="env/dec/{{ name }}.env"
    [[ -f $target ]] || { echo "missing $target" >&2; exit 1; }
    if [[ -e .env || -L .env ]]; then
      if [[ -L .env ]] && [[ $(readlink .env) == env/dec/*.env ]]; then
        rm -f .env
      else
        echo "refusing to replace unmanaged .env (not a symlink into env/dec/)" >&2
        exit 1
      fi
    fi
    ln -s "$target" .env
    echo ".env -> $target"

# Deactivate: remove the managed ./.env symlink (never an unmanaged file).
[group('env')]
env-unuse:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{ justfile_directory() }}"
    if [[ -L .env ]] && [[ $(readlink .env) == env/dec/*.env ]]; then
      rm -f .env; echo "removed .env symlink"
    elif [[ -e .env ]]; then
      echo "refusing to remove unmanaged .env" >&2; exit 1
    else
      echo "no .env to remove"
    fi

# ─── compatibility: ores-sops recipe names ──────────────────────────────────
# The first rollout of this convention named a few recipes differently (they
# delegated to the `ores-sops` wrapper). The self-contained module above covers
# the same operations; keep the old names working so docs, CI and muscle memory
# do not break.
alias env-audit := env-check
