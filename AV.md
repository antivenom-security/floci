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

> [!WARNING]
> **Merge upstream into `av/main`. Never rebase or force-push it.** The antivenom monorepo pins `av/main` commits by ID in its `floci/` submodule. A rebase gives every commit a new ID and drops merge commits. After a force-push, the pinned commit is on no branch, and `git submodule update` can fail for every antivenom checkout.
>
> `just floci-sync` still rebases and force-pushes. **Don't run it** until it's changed to merge. Sync by hand with the steps below.

Upstream releases on the 15th and the last day of each month. After each release, from the monorepo root:

1. `git -C floci fetch upstream && git -C floci fetch origin`
2. Mirror upstream into the fork's `main`, a fast-forward only: `git -C floci push origin upstream/main:refs/heads/main`
3. Update `av/main`: `git -C floci checkout av/main && git -C floci merge --ff-only origin/av/main`
4. Merge upstream into it: `git -C floci merge upstream/main`. Resolve any conflicts. Commits must be signed (`commit.gpgsign`), or the fork's PR Hygiene check fails.
5. Push normally, with no force: `git -C floci push origin av/main`

Then run `just floci-check` and the full test suite. The suite is too heavy for an 8 GB Mac: use the fork's CI on a PR, or a bigger Linux box running CI's four shards (`.github/ci/partition.sh`). Rebuild the image with `just floci-image`, and commit the new submodule pointer in the monorepo.
