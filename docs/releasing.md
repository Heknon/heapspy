# Releasing

heapspy ships as two PyPI projects:

| Project | Built from | Contents |
|---|---|---|
| `heapspy` | root `pyproject.toml` (maturin, `bindings = "bin"`) | the `heapspy` binary, one wheel per platform, plus an sdist |
| `heapspy-mcp` | `python/heapspy-mcp` (hatchling) | pure-Python MCP server, one `py3-none-any` wheel plus an sdist |

`.github/workflows/release.yml` builds and publishes both. It runs only on a
pushed `v*` tag and on manual dispatch.

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
2. If `python/heapspy-mcp` exists, set the same version in its
   `pyproject.toml` and in `heapspy_mcp/__init__.py`.
3. Update `Cargo.lock`:

   ```sh
   cargo update --workspace
   ```

4. Run the local checks from `CONTRIBUTING.md`, then:

   ```sh
   python3 scripts/check-version.py v0.2.0
   ```

5. Commit, open a PR, and merge it to `master`.
6. Tag the merge commit on `master` and push the tag:

   ```sh
   git checkout master
   git pull
   git tag -a v0.2.0 -m "heapspy 0.2.0"
   git push origin v0.2.0
   ```

7. Watch the **Release** workflow in the Actions tab. On success:
   - both projects are on PyPI,
   - a GitHub release named after the tag has the binaries
     (`heapspy-v0.2.0-<target>.tar.gz` / `.zip`) and `SHA256SUMS` attached,
     with notes generated from merged PRs.

If the version check fails, the workflow stops before building. Delete the
tag (`git push --delete origin v0.2.0`, `git tag -d v0.2.0`), fix the
versions, and tag again.

If a build fails, nothing has been published. Fix it on `master`, move the tag
to the fixed commit, and push it again. If PyPI already accepted some files,
do not reuse the version: PyPI never accepts the same file name twice. Bump to
the next patch version instead.

## What the workflow builds

| Job | Output |
|---|---|
| `check-version` | runs `scripts/check-version.py`; detects `python/heapspy-mcp` |
| `wheels` | `heapspy` wheels for `x86_64-unknown-linux-gnu` (manylinux2014), `aarch64-unknown-linux-gnu` (manylinux2014, cross-compiled), `x86_64-unknown-linux-musl` (musllinux_1_2), `x86_64-pc-windows-msvc`; a `.tar.gz` or `.zip` of each binary |
| `sdist` | `heapspy` sdist |
| `mcp` | `heapspy-mcp` sdist and wheel, built with `uv build`. Skipped when `python/heapspy-mcp` is not in the commit |
| `publish-pypi` | tag pushes only: uploads both projects to PyPI |
| `publish-testpypi` | manual dispatch with `publish: testpypi` only: uploads both projects to TestPyPI |
| `github-release` | tag pushes only, after `publish-pypi` succeeds: creates the GitHub release |

The `heapspy` wheels contain only the binary, so they are tagged
`py3-none-<platform>` and install on any Python 3.8 or later. The x86_64 Linux
and Windows wheels are installed and run (`heapspy --version`) as part of the
build.

## Test with TestPyPI

1. In the Actions tab, open **Release**, click **Run workflow**, pick the
   branch, and set **publish** to `testpypi`.
2. The run builds everything and uploads to TestPyPI. It does not publish to
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

Manual dispatch with **publish** set to `none` only builds. Use it to check
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

- `pypi`. Recommended: under **Deployment branches and tags**, choose
  **Selected branches and tags** and add the tag rule `v*`. Optionally add
  required reviewers, so each PyPI upload waits for approval.
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
