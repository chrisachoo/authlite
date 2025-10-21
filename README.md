## 🛡️ authlite — Lightweight, framework-agnostic auth for TypeScript

Lightauth is a tiny authentication core that focuses on: light footprint, great DX, web standards (HttpOnly cookies, HMAC tokens), and no vendor lock-in. Start with Drizzle + SQLite today; Postgres and Prisma are on the roadmap.

### Highlights

- **Email + Password** out of the box (opt-in)
- **Social OAuth** (GitHub today; Discord/Microsoft included; more later)
- **Session cookies** with HttpOnly + SameSite by default
- **Drizzle adapter** included; bring-your-own DB by implementing a small adapter
- **Framework-agnostic** core; examples for Hono

---

## Installation

Pick one of the DB stacks (SQLite shown). Using pnpm:

```bash
pnpm add authlite drizzle-orm @libsql/client
# or if you use better-sqlite3:
pnpm add authlite drizzle-orm better-sqlite3
```

Dev tools (optional but recommended):

```bash
pnpm add -D vitest typescript eslint prettier
```

---

## Quick start (Hono + Drizzle SQLite)

1. Create or reuse your Drizzle DB instance (SQLite locally, LibSQL/Turso in production):

```ts
// db.ts
import { createClient as createLibsqlClient } from "@libsql/client"
import { Database } from "bun:sqlite"
import { drizzle } from "drizzle-orm/bun-sqlite"
import { drizzle as drizzleLibsql } from "drizzle-orm/libsql"
import * as schema from "./schema" // you can copy `src/db/schema.ts`

export const db = (() => {
  if (process.env.NODE_ENV === "production") {
    const client = createLibsqlClient({ url: process.env.DB_URL as string })
    return drizzleLibsql(client)
  }
  const sqlite = new Database(process.env.DB_FILE_NAME as string)
  return drizzle(sqlite, { schema })
})()
```

2. Initialize Lightauth:

```ts
// auth.ts
import { createAuth } from "authlite"
import { drizzleSQLiteAdapter } from "authlite/drizzle-sqlite"
import type { AuthConfig } from "authlite/types"
import { db } from "./db"

export const auth = createAuth({
	database: drizzleSQLiteAdapter(db),
	emailAndPassword: { enabled: true },
	secret: "replace_me_with_strong_secret",
	session: { cookieName: "authlite", ttlMs: 1000 * 60 * 60 * 24 * 7 },
	socialProviders: {
		github: { clientId: "GITHUB_CLIENT_ID", clientSecret: "GITHUB_CLIENT_SECRET" }
	}
} satisfies AuthConfig)
```

3. Wire up routes in Hono:

```ts
// server.ts
import { Hono } from "hono"
import { auth } from "./auth"

const app = new Hono()

app.post("/signup", async (c) => {
	const body = await c.req.json()
	const res = await auth.api.signUp!(body) // enabled via emailAndPassword
	return c.json(res)
})

app.post("/signin", async (c) => {
	const body = await c.req.json()
	const res = await auth.api.signIn!(body)
	return c.json(res)
})

app.get("/session", async (c) => {
	const session = await auth.api.getSession({ headers: c.req.raw.headers })
	return c.json(session)
})

app.post("/signout", async (c) => {
	const token = c.req.cookie("authlite") // or read from headers
	if (token)
		await auth.api.revokeSession(token)
	return c.json({ ok: true })
})
```

That’s it. You’ll get a `Set-Cookie` on signup/signin and `auth.api.getSession` will read it using the request headers.

---

## API surface

```ts
const auth = createAuth(config)

// cookies/session
auth.api.getSession({ headers })
auth.api.createSession({ meta: {/* optional */}, userId })
auth.api.revokeSession(token)
auth.api.revokeAllForUser(userId)
auth.api.rotateSession({ headers })
auth.api.listDevices(userId)

// credentials (enable with emailAndPassword)
auth.api.signUp({ email, name: "optional", password })
auth.api.signIn({ email, password })
// optional verification + reset (credentials only)
auth.api.requestEmailVerification({ userId })
auth.api.verifyEmail({ token })
auth.api.requestPasswordReset({ email })
auth.api.resetPassword({ newPassword, token })

// oauth (configure socialProviders)
auth.api.oauthRedirect(provider, { redirectUri: "optional", state: "optional" })
auth.api.oauthCallback(provider, { code, redirectUri: "optional", state: "optional" })
```

Config shape (essentials):

```ts
type AuthConfig = {
	secret: string
	database: DrizzleAdapter
	session?: { cookieName?: string, ttlMs?: number }
	emailAndPassword?: { enabled: boolean }
	socialProviders?: Partial<{ github: { clientId: string, clientSecret: string } }>
	cache?: null | RedisCacheAdapter
}
```

---

## Adapters (bring your own DB)

Lightauth is not tied to a specific ORM. Today we ship a Drizzle + SQLite adapter. To support other databases/ORMs, implement the small `DrizzleAdapter` interface (see `src/types.ts`). Minimal required methods:

- `findUserById(id)`
- `findSessionByHash(hash)`
- `createSession(userId, tokenHash, expiresAt, meta?)`
- `revokeSession(hash)`

Optional (enables more features):

- Credentials: `findUserByEmail`, `createUser`, `createAccount`, `findAccountByProvider`
- OAuth: `createAccount`, `findAccountByProvider`
- Verification: `createVerification`, `findVerificationByToken`, `deleteVerification`
- Bulk: `revokeAllForUser`

If you ship a Postgres or Prisma adapter, export it from your app and pass it into `createAuth`.

---

## Web standards and security

- Sessions are stored as opaque tokens (client) + HMAC-SHA256 (server) with your app secret.
- Cookies use `HttpOnly` and `SameSite` by default. Set `secure: true` in production and serve over HTTPS.
- Token rotation helper is available; consider rotating every few hours via `session.rotateEveryMs`.
- No `process.env` reading inside the library; you pass config from your app.
- Optional Redis cache adapter can reduce DB calls for session reads.

---

## Testing

```bash
pnpm test
```

We use Vitest. The repo includes a minimal in-memory test to validate signup/session.

---

## Hono helpers

Small utilities to keep your app code clean (optional):

```ts
import { guard, sessionMiddleware } from "authlite"
import { auth } from "./auth"

app.use("*", sessionMiddleware(auth))
app.get("/me", guard(), c => c.json({ user: c.get("user") }))
```

---

## Import map summary

- **Core API**: `import { createAuth } from "authlite"`
- **Types**: `import type { AuthConfig, DrizzleAdapter } from "authlite/types"`
- **Adapters**: `import { drizzleSQLiteAdapter } from "authlite/drizzle-sqlite"`
- **Middleware helpers**: `import { guard, sessionMiddleware } from "authlite"`

This structure keeps imports predictable and tree-shakeable.

---

## Minimal usage guide

1) Configure DB and adapter

```ts
import { drizzleSQLiteAdapter } from "authlite/drizzle-sqlite"
import { db } from "./db"
```

2) Create the auth instance

```ts
import { createAuth } from "authlite"
import type { AuthConfig } from "authlite/types"

export const auth = createAuth({
	secret: process.env.AUTH_SECRET!,
	database: drizzleSQLiteAdapter(db),
	emailAndPassword: { enabled: true }
} satisfies AuthConfig)
```

3) Use the API in your routes

```ts
// signup/signin
await auth.api.signUp!({ email, password })
await auth.api.signIn!({ email, password })

// sessions
const session = await auth.api.getSession({ headers: req.headers })
await auth.api.revokeSession(token)
```

---

## Contributing (git-flow)

This repo uses git-flow for branching and releases. See the excellent
[git-flow cheatsheet](https://danielkummer.github.io/git-flow-cheatsheet/).

Initialize git-flow in the repo:

```bash
git flow init
```

Create a feature branch:

```bash
git flow feature start my-feature
# ...commit work...
git flow feature finish my-feature
```

Cut a release:

```bash
git flow release start 1.1.0
# ...bump version, changelog, fixes...
git flow release finish 1.1.0
git push --follow-tags
```

Hotfix from production:

```bash
git flow hotfix start 1.1.1
# ...fix...
git flow hotfix finish 1.1.1
git push --follow-tags
```

---

### License

MIT

---

### Maintainers

This project is maintained by:

- [chrisachoo](https://github.com/chrisachoo) (GitHub)

---

## Roadmap (keep it light, grow carefully)

- Postgres adapter (Drizzle)
- Prisma adapter
- More OAuth providers (Google, Apple, etc.)
- Email verification + password reset flows
- Session rotation + device metadata helpers
- First-party middleware snippets (Hono, Elysia)

Have a request? Open an issue.

---

## License

MIT © 2025
