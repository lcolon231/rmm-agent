# Coding standards

Judgement calls for review. A rule a linter can check lives in that linter's config instead: `dashboard/eslint.config.mjs`, `server/ruff.toml` / `pyproject.toml`.

## Dashboard

- **Pin a page's 404.** A new server page that maps an API 404 to `notFound()` has a page-tier test pinning it. That branch is the client boundary: a client the operator cannot see must look exactly like a missing one. See "Component and page tier" in `dashboard/AGENTS.md` for how to test a page.
