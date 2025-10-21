import type { AuthInstance } from "./types"

export function sessionMiddleware(auth: AuthInstance) {
	return async (c: any, next: any) => {
		const session = await auth.api.getSession({ headers: c.req.raw.headers })
		c.set("user", session?.user ?? null)
		c.set("session", session?.session ?? null)
		await next()
	}
}

export function guard() {
	return async (c: any, next: any) => {
		const user = c.get("user")
		if (!user)
			return c.json({ error: "unauthorized" }, 401)
		await next()
	}
}
