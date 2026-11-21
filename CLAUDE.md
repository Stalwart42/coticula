# CLAUDE.md — Coticula

> **Name:** Coticula (koh-TIK-yoo-lah) — Latin for "touchstone," the stone assayers used to test gold.
> **Domain (for now):** coticula.kineticdevops.com — a subdomain of Brent's existing Kinetic DevOps domain, so no new registration needed. Later options: coticulahq.com (available 2026-11-21); coticula.sh if Phase 1 ships, for `curl coticula.sh | sh`. Until then the install line is `curl -fsSL https://coticula.kineticdevops.com/install.sh | sh`.
> **Live (2026-11-21):** Cloudflare Worker `coticula` (account Brent.willoughby74@gmail.com's Account) bound as a custom domain on zone kineticdevops.com. Serves a noindex placeholder page at `/`, a stub `/install.sh` that only prints "not released yet", and `robots.txt` disallowing all. Remove noindex/robots at launch.
> **Brand family:** Coticula = the platform · Sigillum ("seal") = the trust badge · The Collegium ("guild") = paid community (joincollegium.com was available 2026-11-21).
> Formerly "Assay" (dropped: crowded with existing AI code-verification tools).

> Status: **ACTIVE — Phase 1 built (2026-11-21).** Brent un-parked it and asked for Phase 1 + the site. Phases 2–3 stay parked until he says otherwise.

## Phase 1 status (v0.1.0)
- **Scanner:** Python 3.9+, zero dependencies, `src/coticula/`. Checks: secrets, deps (OSV.dev), ai (prompt injection / hidden Unicode / MCP tool text), manifest (`coticula.json` vs detected network/subprocess/env/file-write/eval), quality (0–100 score). Commands: `scan`, `init`, `badge`. 14 pytest tests; scanner scans itself to the Scanned tier.
- **Site:** `site/` bundles landing, docs, waitlist API, `install.sh` and the wheel into one Worker (`python site/build.py` → `site/dist/worker.js`). Deploy: `npx wrangler deploy -c site/wrangler.toml`. Waitlist = KV namespace `coticula-waitlist` (id 518c729cfae640a196cc26cced177e37), keys `email:<address>`.
- **Release flow:** bump version in `pyproject.toml` + `src/coticula/__init__.py` → `python -m build --wheel` → `python site/build.py` → wrangler deploy. The installer verifies the wheel's SHA-256.
- **Still noindex** (meta tags, X-Robots-Tag, robots.txt). Remove all three at public launch.
- **Open decisions:** license (needed before making the repo public), PyPI publishing, OSV check on Mac not yet verified live (sandbox had no network).
> Owner: Brent Willoughby · Parent entity (planned): Monolithic LLC
> Last updated: 2026-11-21

## What this is
An open, security-vetted library and community for reusable code components — MCP servers, agent skills,
plugins, libraries, modules — built by AI-assisted and traditional developers alike. The goal is to stop
everyone rebuilding the same things by giving them a trusted place to find, share, and sell parts that
bolt onto other projects safely.

**One-line pitch:** "Every component here was scanned, sandboxed and quality-checked — and you can see the receipts."

## Core principles
1. **Open but verified.** Anyone can publish; nothing gets a trust badge without passing the pipeline.
2. **Receipts, not promises.** Show scan results, SBOM, permissions, and signatures. Never claim "secure" — say "passed these checks."
3. **Build once.** Duplicate detection on every submission and request.
4. **Quality over volume.** Anti-slop gate: tests, docs, clear interface required.
5. **Automate everything.** Human time only for Certified-tier audits and edge-case appeals.

## Vetting pipeline
| Stage | What | Tools (candidates) |
|---|---|---|
| 1. Identity | GitHub OAuth, 2FA required, signed releases | GitHub OAuth, Sigstore/cosign |
| 2. Manifest | Declared permissions: network, files, env, tools called | Custom schema (JSON) |
| 3. Static | Secrets, SAST, dependency CVEs, licenses, SBOM | gitleaks, Semgrep/CodeQL, OSV-Scanner, Syft |
| 4. Dynamic | Run in isolated sandbox; compare observed vs declared behavior | Firecracker/gVisor VMs (cloud, never Brent's Mac) |
| 5. AI-specific | Prompt-injection / hidden-instruction scan of skills, prompts, MCP tool descriptions | LLM classifier + rules |
| 6. Quality | Tests present and meaningful, docs, interface; LLM slop review; duplicate check vs catalog | Coverage tools, LLM review, embedding similarity |
| 7. Continuous | Rescan on new CVEs; revoke and notify dependents | Scheduled jobs + OSV feed |

### Trust tiers
- **Scanned** — stages 1–6 automated. Cheap.
- **Reviewed** — Scanned + peer review by reputation-qualified members.
- **Certified** — Reviewed + paid human audit.

## Monetization
- **Free:** browse, use Scanned components, free CLI/GitHub Action scanner for public repos (growth engine).
- **Publisher, ~$5–10/mo:** automated vetting with a monthly submission quota, badge, profile.
- **Pro scan:** private repos, deeper sandbox runs, CI integration.
- **Team/Org:** private libraries, policy rules ("Certified only"), audit logs — main revenue.
- **Paid components:** revenue share (app-store model), Stripe Connect payouts.
- **Certification:** per-audit fee.
- Reviewers earn credits/fee share for peer reviews.

Note: costs scale with submissions, not members — price publishers/teams, not browsers.

## Social layer (reputation built on shipped work)
- Profiles show shipped, vetted components, reviews done, and downstream usage — not likes/followers.
- **Requests board:** post a need → dedupe check → if missing, open as a bounty; builders claim it.
- **Reviewer guild:** earn review rights through reputation; paid in credits or share of fees.
- **Composition graph:** see what's built on what; attribution (and revenue) flows upstream.
- **Build logs** instead of generic posts: changelogs, release notes, postmortems.
- Monthly themed challenges (e.g., "best networking MCP server").
- Keep discussion on GitHub Discussions at first — low moderation overhead.

## Go-to-market (reach people who already feel the pain)
1. **Free scanner + README badge** — viral loop; every badge links back.
2. **Automated "state of security" reports** — scan public skills/MCP servers monthly, publish findings. Newsworthy, data-driven, fully automated.
3. **Catalog as an MCP server** — agents query the library directly; AI tools become distribution.
4. **Be listed where devs already look:** claudemarketplaces.com, Smithery, MCP Registry.
5. **Communities:** r/ClaudeAI, r/mcp, r/AI_Agents, Latent Space Discord, Show HN, dev.to, daily.dev Squads.
6. **Credibility:** Brent's CISSP + 25 years networking → seed a networking/NetOps category on day one.
7. **Auto-generated weekly newsletter** of newly vetted components (Brevo).

## Automation plan (minimal Brent-hours)
- **Auth:** GitHub OAuth only — no passwords to manage.
- **Billing:** Stripe Checkout + Customer Portal — no custom billing code.
- **Site/data:** Cloudflare Pages/Workers + D1 + R2.
- **Scanning:** queue → isolated cloud sandboxes. **Exception to Brent's "use my Mac" CI rule:** untrusted
  submissions must never run on his personal machine. Brent's Mac is fine for building/testing Coticula's own code.
- **Moderation:** automated rules + report button + reviewer guild; Brent handles appeals only.
- **Content:** reports, newsletter, and digests generated on schedule.
- **Support:** docs + FAQ + AI support bot.

## Phased roadmap (smallest money first)
- **Phase 0 — Park (now):** this doc + whiteboard. No code.
- **Phase 1 — Scanner (smallest sellable thing):** CLI + GitHub Action scanning MCP servers/skills; free for public, paid Pro for private. Badges.
- **Phase 2 — Catalog:** vetted directory + MCP server + publisher subscriptions.
- **Phase 3 — Community:** requests/bounties, reviewer guild, paid components, team plans.

## Risks / open questions
- **Liability:** wording + ToS reviewed by a lawyer; operate under Monolithic LLC.
- **Competition:** Socket.dev, Snyk, MseeP, mcp-marketplace.io. Differentiator = community + quality gate + dedupe + AI-specific checks.
- **Cold start:** seed with Brent's own components and curated imports.
- **Sandbox cost and escape risk** — budget and isolation design needed before Phase 1.
- **Name:** Web check (2026-11-21) found no software product named Coticula. Still to do: USPTO search, classes 009 and 042, before branding spend.

## Conventions for Claude working on this
- Recommend the Claude model at the start of each task; pause for Brent to switch before the next step.
- Give Mac commands as one copyable chained block.
- Prefer Brent's Mac over paid GitHub Actions minutes — except never for running untrusted submissions.
- Keep scope to the current phase; log new ideas under "Parking lot" instead of building them.

## Parking lot
- (add ideas here)
