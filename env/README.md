# Environment files

Secrets for `embedded-alerts/eal-api` are **committed, encrypted**, with [sops] + [age],
following the fleet-wide convention already used by fiducia-cloud, shared-auth,
benefactor-cc, 3FA-app and zed-pkg (the `ORESoftware/ores-sops` contract).

```
env/enc/dev.env.enc     ciphertext — committed. This is the source of truth.
env/enc/prod.env.enc    ciphertext — committed. Protected-operator recipients.
env/dec/dev.env         plaintext  — gitignored, mode 0600, disposable.
env/dec/prod.env        plaintext  — gitignored, mode 0600, disposable.
.env                    relative managed symlink -> env/dec/<name>.env
```

`env/dec` is a build artifact. Delete it whenever you like and regenerate with
`just env-decrypt`; nothing there is authoritative. `.env` in the repo root is
only ever a symlink into `env/dec/` (`just env-use <name>`), never a copied
plaintext file; the recipes refuse to clobber an unmanaged `.env`.

`dev.env.enc` was seeded from `.env.example` — every value in it is the
placeholder from the example, so the **variable names are right and the
values still need filling in** (`just env-edit dev`). `prod.env.enc` starts
empty and is encrypted to a *different* recipient set (see `.sops.yaml`).

## First run on a new machine

```sh
just env-keygen     # creates your age key (never overwrites an existing one)
just env-whoami     # prints your public recipient — send it to a maintainer
```

A maintainer adds your recipient to `.sops.yaml`, runs `just env-rekey`, and
commits. Until then you cannot decrypt anything. After that:

```sh
just env-decrypt    # env/enc/*.env.enc -> env/dec/*.env
just env-use dev    # .env -> env/dec/dev.env
just env-check      # confirms nothing plaintext is tracked and all files decrypt
```

## Day to day

| Command | What it does |
|---|---|
| `just env-list` | environments and the variable *names* in each (never values) |
| `just env-decrypt [name…]` | ciphertext → `env/dec/*.env`, mode 0600 |
| `just env-use <name>` | decrypt and point `./.env` at `env/dec/<name>.env` |
| `just env-unuse` | remove the managed `./.env` symlink |
| `just env-edit <name>` | open the decrypted file in `$EDITOR`; plaintext never hits disk |
| `just env-encrypt [name…]` | fold `env/dec/*.env` edits back into the ciphertext |
| `just env-status` | which variables differ between your `env/dec` and the ciphertext |
| `just env-run <name> <cmd…>` | run `cmd` with those variables exported, no plaintext on disk |
| `just env-new <name>` | start a new environment |
| `just env-rekey` | re-sync recipients after editing `.sops.yaml` |
| `just env-check` | fail-closed audit — safe to run in CI |
| `just env-doctor` | report which tools / keys this host has |
| `just env-clean` | wipe `env/dec` |

Prefer `just env-edit` over decrypt-edit-encrypt. Both work, but `env-edit`
re-encrypts only the values you actually changed, so the diff names them:

```
-DATABASE_URL=ENC[AES256_GCM,data:OG3trz…]
+DATABASE_URL=ENC[AES256_GCM,data:9fKq2a…]
```

`just env-encrypt` uses the same mechanism, so it is equally clean. A bare
`sops encrypt` is not — it gives every line a fresh IV and rewrites the whole
file, which makes review useless and guarantees merge conflicts. Don't call
sops directly; use the recipes.

## Running things

`.envrc` deliberately loads **no secrets**. Production is opt-in per command:

```sh
just env-run prod cargo run --release
just env-run dev ./scripts/migrate.sh
```

`env-run` streams the values straight into the child process. Nothing is
written to disk, so an interrupted run can't leave `env/dec/prod.env` behind.
Tools that insist on a real file get one via `just env-use dev` (the `.env`
symlink) or `just env-decrypt`.

## What is and isn't hidden

Variable **names are plaintext** in `env/enc/*.env.enc`; only values are
encrypted. That is the point — it makes diffs reviewable and lets `env-list`
work without a key. Never encode a secret in a variable *name*. Comments are
encrypted, so anything explanatory belongs in this file instead.

Two format limits, inherited from sops' dotenv parser:

- **No multi-line values.** A PEM must be a single quoted line with literal
  `\n` escapes between its standard header, encoded body, and footer. Never
  commit a real key or a credential-shaped example.
- **Blank lines are dropped** on round-trip. Cosmetic only.

## Containers

Decryption happens at `docker run`, **never** at `docker build`. A secret
decrypted during a build is written into an image layer and stays there — a
later `RUN rm` does not remove it, and `--build-arg` is worse still because it
lands in `docker history`.

```sh
just env-docker-run dev ghcr.io/embedded-alerts/eal-api:dev
just env-k8s-secret prod | kubectl apply -f -
```

Nothing is baked into the image: no sops binary, no ciphertext, no entrypoint
script. `sops exec-env` shells out to `/bin/sh` in both modes, which rules it
out on distroless images, and decrypting host-side and injecting with
`--env-file` leaves the application as **PID 1** so `docker stop` delivers
SIGTERM straight to it. The trade-off, stated plainly: `--env-file` values are
visible in `docker inspect`. For real deployments use `env-k8s-secret` and let
the platform hold the secret.

All paths share one parser (`.just/dotenv.py`) so the same encrypted file
yields byte-identical values everywhere.

## Rules

- Never commit anything from `env/dec/`. `.gitignore` and `just env-check`
  both block it; don't defeat them with `git add -f`.
- Never commit a private age key. They belong only in
  `~/Library/Application Support/sops/age/keys.txt` (macOS) or
  `~/.config/sops/age/keys.txt` (Linux), mode 0600.
- Removing a recipient does not un-leak anything. Rotate the credentials too.
- Files ending in `.env` are gitignored repo-wide. If a repo has a legitimate
  non-secret `*.env` (for example generated cluster topology), allow it with an
  explicit `!` rule in `.gitignore` — deny by default, permit narrowly.
- `.just/env.just` and `.just/dotenv.py` are a **shared module**, byte-identical
  across the fleet. Fix them in one repo and propagate; do not fork per repo.

[sops]: https://github.com/getsops/sops
[age]: https://github.com/FiloSottile/age

## Compatibility with the `ores-sops` recipe names

The first rollout of this convention delegated to the `ores-sops` wrapper and
used a few different recipe names. They still work as aliases:

| old name | now |
|---|---|
| `just env-audit` | `just env-check` |
| `just env-lock` | `just env-clean` |
| `just env-key` | `just env-whoami` |
| `just env-diff` | `just env-status` |
| `just env-refresh` | `just env-decrypt` |

Containers built from this repo's `Dockerfile` carry `scripts/sops-entrypoint.sh`
and decrypt at `docker run` when `SOPS_AGE_KEY` / `SOPS_AGE_KEY_FILE` is
supplied; without a key they run the command unchanged. `just env-docker-run`
(host-side decryption, `--env-file` injection) works for any image, including
distroless ones.
