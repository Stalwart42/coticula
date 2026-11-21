# Coticula

**Test before you trust.** Coticula (koh-TIK-yoo-lah, Latin for *touchstone*) scans MCP servers, agent skills, plugins and reusable code for the problems a careful reviewer would catch — before you bolt them onto your project.

```
curl -fsSL https://coticula.kineticdevops.com/install.sh | sh
coticula scan .
```

## What it checks

| Check | What it finds |
|---|---|
| `secrets` | Leaked API keys (Anthropic, OpenAI, AWS, GitHub, Slack, Stripe, Google), private keys, committed `.env` files, high-entropy hard-coded secrets. Snippets are always redacted. |
| `deps` | Known vulnerabilities in pinned Python and npm dependencies via [OSV.dev](https://osv.dev), plus unpinned versions. |
| `ai` | Text that tries to steer the model reading it: instruction overrides, "don't tell the user", exfiltration requests, auto-approve instructions, hidden HTML comments, encoded blobs — in `SKILL.md`, prompts, `CLAUDE.md`/`AGENTS.md` and MCP tool descriptions. Invisible Unicode (tag-character smuggling, bidi controls, zero-width) anywhere. |
| `manifest` | Compares what your code does (network, subprocess, environment variables, file writes, eval) against what `coticula.json` declares. |
| `quality` | Missing README/tests/license, tests that can't fail, placeholders, swallowed errors, oversized files. Produces a 0–100 quality score. |

A project with no **high** or **critical** findings earns the **Scanned** tier and a badge.

## Usage

```
coticula scan [PATH]                 # text report (default: current dir)
coticula scan . --format json -o report.json
coticula scan . --format markdown    # for PR comments
coticula scan . --fail-on medium     # stricter gate (default: high)
coticula scan . --only ai --only secrets
coticula scan . --exclude "examples/**"
coticula scan . --offline            # skip the OSV lookup
coticula init                        # generate coticula.json from detected capabilities
coticula badge . -o coticula.svg     # README badge
```

Exit codes: `0` pass · `1` findings at or above `--fail-on` · `2` error.

Silence a single line with a trailing `coticula:ignore` comment. Skip paths with `"ignore"` globs in `coticula.json`.

## Permission manifest

```json
{
  "name": "my-mcp-server",
  "permissions": {
    "network": ["api.github.com"],
    "filesystem": "read",
    "env": ["GITHUB_TOKEN"],
    "subprocess": false
  },
  "ignore": ["tests/fixtures/**"]
}
```

`network` and `env` accept `true`, `false` or a list (lists are documentation in v0.1; host-level enforcement arrives with sandboxed runs). `filesystem` is `none`, `read` or `write`.

## CI

Run it anywhere Python 3.9+ runs. On GitHub:

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: |
    curl -fsSL https://coticula.kineticdevops.com/install.sh | sh
    coticula scan . --format markdown
```

The markdown report is also appended to the job summary automatically when `GITHUB_STEP_SUMMARY` is set.

## Limits (v0.1)

Detection is static and pattern-based. It will miss things a determined attacker hides well, and it will occasionally flag safe code. "Scanned" means *passed these checks*, not *guaranteed safe*. Sandboxed runtime verification and human review tiers are on the roadmap.

## Development

```
pip install -e . pytest
pytest
coticula scan .        # Coticula scans itself in CI
```

Docs: https://coticula.kineticdevops.com/docs

License: to be decided before public release.
