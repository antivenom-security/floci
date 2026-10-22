# antivenom fork

This is `antivenom-security/floci`, a fork of [`floci-io/floci`](https://github.com/floci-io/floci) that makes Floci emit AWS-faithful telemetry (CloudTrail, VPC Flow Logs, Route 53 Resolver query logs). The design lives in the antivenom monorepo at `design/20261022_03_floci_fork_telemetry.md`, which links this repo as a submodule at `floci/`.

## Branches

- `main` mirrors upstream `main`. Fast-forward only, never commit to it.
- `av/main` is upstream plus our work. The monorepo submodule tracks it.
- `av/p<N>-<slug>` holds one phase of work. It lands as a PR into `av/main` (ready for review, not a draft), squash-merged.

Code follows this repo's `AGENTS.md`, so the work can later go upstream as a batch PR without a rewrite.

## Remotes

```bash
git remote add upstream https://github.com/floci-io/floci.git
```

`origin` is the fork.

## Images

The product image is the JVM image (see the design spec's Decisions). From the monorepo root, after `brew bundle && just setup`:

- `just floci-image` builds it from the working copy with `docker/Dockerfile.jvm-package`, tagged `antivenom/floci:<pom-version>-av.<short-sha>`. The short SHA is the checked-out commit, normally `av/main`.
- `just floci-image-native` builds a native image (`-native` tag). It needs about 16 GB of RAM and is only checked before an upstream PR. The fork's `Compatibility Tests` workflow on a PR does the same on amd64 and arm64.

## Syncing with upstream

Upstream releases on the 15th and the last day of each month. After each release, run `just floci-sync` from the monorepo root. It does this:

1. `git fetch upstream`
2. Fast-forward fork `main` to `upstream/main`.
3. Rebase `av/main` onto `upstream/main`.
4. Push with `--force-with-lease`.

Then run `just floci-check` and `just floci-test`, rebuild the image, and commit the new submodule pointer in the monorepo.
