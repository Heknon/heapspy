# Releasing

heapspy ships as two PyPI projects:

| Project | Built from | Contents |
|---|---|---|
| `heapspy` | root `pyproject.toml` (maturin, `bindings = "bin"`) | the `heapspy` binary, one wheel per platform, plus an sdist |
| `heapspy-mcp` | `python/heapspy-mcp` (hatchling) | pure-Python MCP server, one `py3-none-any` wheel plus an sdist |

`.github/workflows/release.yml` builds and publishes both. Releasing is a
version bump: when a commit on `master` carries a version that has no `vX.Y.Z`
tag yet, the workflow tests it, publishes it, tags it and creates the GitHub
release. Every other push to `master` stops after a few seconds without doing
anything.

## Versions

The version in the root `Cargo.toml` is the source of truth:

```toml
[workspace.package]
version = "0.1.0"
```

The `heapspy` wheel takes its version from it (`dynamic = ["version"]` in
`pyproject.toml`). `heapspy-mcp` has its own static version, which must be the
same string, in two places:

- `python/heapspy-mcp/pyproject.toml`: `[project] version`
- `python/heapspy-mcp/src/heapspy_mcp/__init__.py`: `__version__`

`scripts/check-version.py` checks all of this and the tag. The release
workflow runs it before building anything. Run it yourself first:

```sh
python3 scripts/check-version.py v0.2.0
```

It needs Python 3.11 or later. Use plain `X.Y.Z` versions. Pre-release
versions are not supported yet: Cargo writes `0.2.0-rc.1` where Python writes
`0.2.0rc1`, and the check compares the strings exactly.

## Cutting a release

1. Bump the version in the root `Cargo.toml` (`[workspace.package] version`).
   Also bump the matching `version` entries for the internal crates in
   `[workspace.dependencies]`.
2. Set the same version in `python/heapspy-mcp/pyproject.toml` and in
   `heapspy_mcp/__init__.py`.
3. Update `Cargo.lock`:

   ```sh
   cargo update --workspace
   ```

4. Run the local checks from `CONTRIBUTING.md`, then:

   ```sh
   python3 scripts/check-version.py v0.2.0
   ```

5. Commit, open a PR, and merge it to `master`. Merging is the release: there
   is nothing to tag by hand.
6. Watch the **Release** workflow in the Actions tab. It runs, in order:
   - `gate`: sees that `v0.2.0` has no tag yet,
   - CI (`ci.yml`), E2E (`e2e.yml`) and the live record tests (`record.yml`)
     on the merge commit, Linux and Windows,
   - the version check and all builds,
   - the PyPI upload, as a deployment to the `pypi` environment,
   - the `v0.2.0` tag on the merge commit and the GitHub release, with the
     binaries (`heapspy-v0.2.0-<target>.tar.gz` / `.zip`) and `SHA256SUMS`
     attached and notes generated from merged PRs.

Merges that do not change the version do not release. Only bump the version
in a PR you intend to ship as soon as it merges.

Nothing is published until CI, E2E, the record tests, the version check and
every build have passed. If one fails, fix it in a new PR and merge that: the version is still
untagged, so the next push to `master` releases it. If PyPI already accepted
some files, do not reuse the version: PyPI never accepts the same file name
twice. Bump to the next patch version instead.

The tag and the GitHub release are created only after the PyPI upload
succeeds. If the release job itself fails, re-run it from the run page.

Pushing a `vX.Y.Z` tag by hand still works and runs the same jobs. Use it to
release a commit that is not the tip of `master`. The tag must match the
version in that commit.

## What the workflow builds

| Job | Output |
|---|---|
| `gate` | decides whether this run releases: a `master` push whose version is untagged, a tag push, or a dispatch |
| `ci`, `e2e`, `record` | `ci.yml`, `e2e.yml` and `record.yml` on the release commit |
| `check-version` | runs `scripts/check-version.py`; checks that an existing tag for the version is on this commit; detects `python/heapspy-mcp` |
| `wheels` | `heapspy` wheels for `x86_64-unknown-linux-gnu` (manylinux2014), `aarch64-unknown-linux-gnu` (manylinux2014, cross-compiled), `x86_64-unknown-linux-musl` (musllinux_1_2), `x86_64-pc-windows-msvc`; a `.tar.gz` or `.zip` of each binary |
| `sdist` | `heapspy` sdist |
| `mcp` | `heapspy-mcp` sdist and wheel, built with `uv build`. Skipped when `python/heapspy-mcp` is not in the commit |
| `publish-pypi` | releases only: uploads both projects to PyPI in the `pypi` environment |
| `publish-testpypi` | manual dispatch with `publish: testpypi` only: uploads both projects to TestPyPI |
| `github-release` | releases only, after `publish-pypi` succeeds: tags the commit `vX.Y.Z` if it is not tagged yet and creates the GitHub release |

The `heapspy` wheels contain only the binary, so they are tagged
`py3-none-<platform>` and install on any Python 3.8 or later. The x86_64 Linux
and Windows wheels are installed and run (`heapspy --version`) as part of the
build.

## Test with TestPyPI

1. In the Actions tab, open **Release**, click **Run workflow**, pick the
   branch, and set **publish** to `testpypi`.
2. The run tests and builds everything and uploads to TestPyPI. It does not publish to
   PyPI and does not create a GitHub release, even when run on a tag.
3. Install from TestPyPI in a fresh virtual environment:

   ```sh
   uv venv /tmp/heapspy-test
   uv pip install --python /tmp/heapspy-test/bin/python \
       --index-url https://test.pypi.org/simple/ heapspy
   /tmp/heapspy-test/bin/heapspy --version
   ```

   `heapspy-mcp` depends on packages that are not on TestPyPI, so add PyPI as
   a fallback index for it:

   ```sh
   uv pip install --python /tmp/heapspy-test/bin/python \
       --index-url https://test.pypi.org/simple/ \
       --extra-index-url https://pypi.org/simple/ \
       --index-strategy unsafe-best-match heapspy-mcp
   ```

TestPyPI also refuses a file it already has. The TestPyPI upload uses
`skip-existing`, so a second run with the same version succeeds but uploads
nothing new.

Manual dispatch with **publish** set to `none` runs the tests and builds,
without uploading anything. Use it to check
that all targets still compile and download the artifacts from the run page.

## Build locally

```sh
uvx maturin build --release        # wheel for this machine, in target/wheels/
uvx maturin sdist                  # sdist, in target/wheels/
uv build python/heapspy-mcp        # heapspy-mcp, in python/heapspy-mcp/dist/
```

Check the wheel in a throwaway environment:

```sh
uv venv /tmp/heapspy-wheel
uv pip install --python /tmp/heapspy-wheel/bin/python target/wheels/heapspy-*.whl
/tmp/heapspy-wheel/bin/heapspy --version
```

## One-time setup

These steps are done once by a repository owner, before the first release.

### GitHub environments

In the repository, open **Settings > Environments** and create:

- `pypi`. Under **Deployment branches and tags**, either leave it
  unrestricted or choose **Selected branches and tags** and add both the
  branch `master` and the tag rule `v*`. A rule with only `v*` blocks the
  release from a merge to `master`. Optionally add required reviewers, so
  each PyPI upload waits for approval.
- `testpypi`. Leave branches unrestricted, so the workflow can be dispatched
  from any branch.

No secrets are needed. The publish jobs use OpenID Connect tokens.

### PyPI trusted publishers

The projects do not exist on PyPI before the first upload, so register
*pending* publishers. On <https://pypi.org>, open **Your account >
Publishing**, and under **Add a new pending publisher > GitHub** add one entry
per project:

| Field | `heapspy` | `heapspy-mcp` |
|---|---|---|
| PyPI Project Name | `heapspy` | `heapspy-mcp` |
| Owner | `Heknon` | `Heknon` |
| Repository name | `heapspy` | `heapspy` |
| Workflow name | `release.yml` | `release.yml` |
| Environment name | `pypi` | `pypi` |

The first successful upload creates the project and turns the pending
publisher into a normal one. After that, it is listed under the project's
**Settings > Publishing**.

### TestPyPI trusted publishers

TestPyPI is a separate site with separate accounts. On
<https://test.pypi.org>, add the same two pending publishers, with the
environment name `testpypi` instead of `pypi`.
