# antivenom fork

This is `antivenom-security/floci`, a fork of [`floci-io/floci`](https://github.com/floci-io/floci) that makes Floci emit AWS-faithful telemetry (CloudTrail, VPC Flow Logs, Route 53 Resolver query logs). The design lives in the antivenom monorepo at `design/20261022_03_floci_fork_telemetry.md`, which links this repo as a submodule at `floci/`.

## Branches

- `main` mirrors upstream `main`. Fast-forward only, never commit to it.
- `av/main` is upstream plus our work. The monorepo submodule tracks it.
- `av/p<N>-<slug>` holds one phase of work, squash-merged into `av/main`.

Code follows this repo's `AGENTS.md`, so the work can later go upstream as a batch PR without a rewrite.

## Remotes

```bash
git remote add upstream https://github.com/floci-io/floci.git
```

`origin` is the fork.

## Images

Images are built locally, with no CI: `just floci-image` from the monorepo root runs `make native native-image`. That needs Docker and a JDK 25 on `JAVA_HOME`, and builds for the host arch.

Tag: `antivenom/floci:<pom-version>-av.<short-sha>`. The short SHA is the checked-out commit, normally `av/main`.

## Syncing with upstream

Upstream releases on the 15th and the last day of each month. After each release, run `just floci-sync` from the monorepo root. It does this:

1. `git fetch upstream`
2. Fast-forward fork `main` to `upstream/main`.
3. Rebase `av/main` onto `upstream/main`.
4. Push with `--force-with-lease`.

Then run `just floci-test`, rebuild the image, and commit the new submodule pointer in the monorepo.
