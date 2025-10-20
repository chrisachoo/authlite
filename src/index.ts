import type { AuthInstance } from "./types"

export { createAuth } from "./core/auth"
export { redisCacheAdapter } from "./core/redis-cache"

export type { AuthConfig, AuthInstance, DrizzleAdapter } from "./types"

/**
 * sessionMiddleware is a middleware function that can be used to protect routes
 * @param auth - The auth instance to use
 * @returns A middleware function that can be used to protect routes
 */
export function sessionMiddleware(auth: AuthInstance) {
	return async (c: any, next: any) => {
		const session = await auth.api.getSession({ headers: c.req.raw.headers })
		c.set("user", session?.user ?? null)
		c.set("session", session?.session ?? null)
		await next()
	}
}

/**
 * guard is a middleware function that can be used to protect routes
 * @returns A middleware function that can be used to protect routes
 */
export function guard() {
	return async (c: any, next: any) => {
		const user = c.get("user")
		if (!user)
			return c.json({ error: "unauthorized" }, 401)
		await next()
	}
}

/**
 * createAuth core features
 * - api.getSession: read session from cookie header
 * - api.createSession: issue new session and Set-Cookie
 * - api.revokeSession / revokeAllForUser: invalidate session(s)
 * - Credentials (optional): signUp, signIn, request/verify email, reset password
 * - OAuth: github/discord/microsoft redirect + callback helpers
 * - Sessions: rotateSession and listDevices
 *
 * Hints
 * - Always pass your secret to createAuth. Use a strong, app-specific secret.
 * - Serve over HTTPS and keep cookies HttpOnly and SameSite=Lax or Strict.
 * - For credentials, ensure adapter methods are implemented (createUser, etc.).
 */
