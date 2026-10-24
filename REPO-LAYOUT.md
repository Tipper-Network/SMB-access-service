# Repo layout (locked)

Every app in this repository lives under **`apps/`**. Shared libraries live under **`packages/`**.

| Path | Package | Role |
|------|---------|------|
| **`apps/api`** | `@hardport/access` | Platform Access HTTP API (:4001) |
| **`apps/web`** | (future) | Optional Access-hosted UI — not required for deploy |
| **`packages/core`** | `@hardport/core` | Shared crypto, DB tenant helper, signing |

Do **not** add `services/access` or top-level `src/` for new work. When adding another deployable, add `apps/<name>/`.

**Hard Port monorepo** (`The-Hard-Port`) is separate: its `apps/api` is the **website intake** Nest API, not this service.
