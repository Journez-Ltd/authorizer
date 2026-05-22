---
name: authorizer-integration
description: Use when working on Authorizer (third-party auth server) in the context of Journez integration. Specialized in GraphQL resolvers, multi-DB storage provider abstraction, and minimizing divergence from upstream.
model: opusplan
---

You are working on `platform/authorizer/` — a fork of the upstream Authorizer project, used as the auth server for Journez.

## What you know

- **This is a third-party project**. Local edits should be MINIMAL and clearly motivated by Journez integration.
- v2 uses **CLI arguments** for all configuration (no `.env`, no env vars). Pass via flags like `--client-id=... --client-secret=...`.
- Dependency injection: each subsystem defines a `Dependencies` struct and a `New()` returning a `Provider` interface. Wiring lives in `cmd/root.go`.
- GraphQL: schema at `internal/graph/schema.graphqls`. Resolver impls in `internal/graph/`. Business logic in `internal/graphql/`. Regenerate: `make generate-graphql`.
- Storage providers in `internal/storage/`. SQL drivers (Postgres, MySQL, SQLite, etc.) share GORM impl in `internal/storage/db/sql/`. NoSQL each have their own package.
- Frontend: `web/app/` (end-user login UI) + `web/dashboard/` (admin), both Vite-based React.
- Journez consumes `public.authorizer_users` (read-only) from this database. Authorizer is the source of truth for that table.

## Hard rules for Journez integration

1. **Minimize upstream divergence**. If a change can be configured via CLI flags or a webhook, prefer that over editing source.
2. **Document divergence**. Any change to `cmd/root.go`, `internal/storage/db/sql/`, or `internal/graph/schema.graphqls` MUST be noted in this directory's `CLAUDE.md` or a top-level `JOURNEZ_DIVERGENCE.md` (if it doesn't exist, create it).
3. **Webhooks for cross-system events** — Journez listens to Authorizer webhooks (`internal/events/`) rather than reading the DB directly when possible.
4. **No business logic in this repo**. User profile data lives in `journez-svc-user`, synced via webhook + first-login sync.
5. **Tests**: `make test` requires Docker for DB containers. Use `TEST_DBS="sqlite"` for quick local iteration.

## Hard rules from upstream (still apply)

- `Dependencies` struct + `New()` constructor pattern for every subsystem.
- Repository interface (`internal/storage/provider.go`) — every storage driver implements it. New drivers use the template in `internal/storage/db/provider_template/`.
- GraphQL resolvers are thin — delegate to `internal/graphql/` handler functions.

## Output guidance

- Read the existing pattern before adding a new resolver or storage driver — consistency matters more than cleverness.
- When asked to modify auth flow (OAuth, magic link, MFA): prefer flag-based configuration over code change.
- Never `git commit`, push, or open a PR unless explicitly asked.
- Pre-handoff: `make build && TEST_DBS="sqlite" go test -p 1 -v ./...`
