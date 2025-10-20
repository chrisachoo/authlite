export type CookieOptions = {
	path?: string
	sameSite?: "Lax" | "lax" | "None" | "none" | "Strict" | "strict"
	secure?: boolean
}

/**
 * Build a secure, HttpOnly Set-Cookie header string.
 * Defaults: SameSite=Lax, Secure=true (set false only for local dev over http).
 */
export function buildSetCookie(
	name: string,
	token: string,
	expiresAtMs: number,
	options: CookieOptions = {}
): string {
	const path = options.path ?? "/"
	const sameSite = options.sameSite ?? "Lax"
	const secure = options.secure ?? true
	const expires = new Date(expiresAtMs).toUTCString()

	return `${name}=${encodeURIComponent(token)}; Path=${path}; Expires=${expires}; HttpOnly; SameSite=${sameSite}${
		secure ? "; Secure" : ""
	}`
}

/**
 * Read a cookie value from the Cookie header string.
 */
export function readCookie(cookieHeader: null | string, name: string): null | string {
	if (!cookieHeader)
		return null
	const cookies = cookieHeader.split(";").map(s => s.trim())
	const match = cookies.find(c => c.startsWith(`${name}=`))
	if (!match)
		return null
	return decodeURIComponent(match.split("=")[1])
}
