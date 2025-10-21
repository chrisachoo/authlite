import type { AuthConfig, AuthInstance } from "../types"

import { createId } from "@paralleldrive/cuid2"
import * as v from "valibot"
import { buildSetCookie, readCookie } from "./cookies"
import { genRawToken, hashToken, hashTokenAll, setSecret } from "./crypto"
import { exchangeDiscordCode, exchangeGithubCode, exchangeMicrosoftCode } from "./oauth"
import { hashPassword, verifyPassword } from "./password"
import { parseDeviceFromHeaders } from "./session"

/* Validation schemas */
const signupSchema = v.object({
	email: v.pipe(v.string(), v.email()),
	name: v.string(),
	password: v.pipe(v.string(), v.minLength(8))
})
const signinSchema = v.object({
	email: v.pipe(v.string(), v.email()),
	password: v.string()
})

/**
 * createAuth is the main function to create an auth instance
 * @param config - The configuration for the auth system
 * @returns An auth instance
 */
export function createAuth(config: AuthConfig): AuthInstance {
	setSecret(config.secret)
	const adapter = config.database
	const cache = config.cache ?? null
	const ttlMs = config.session?.ttlMs ?? 1000 * 60 * 60 * 24 * 7
	const cookieName = config.session?.cookieName ?? "authlite"
	const _rotateEveryMs = config.session?.rotateEveryMs ?? 0
	const updateAgeMs = config.session?.updateAgeMs ?? 1000 * 60 * 60 * 24 // default 1 day
	const verificationEmailTTL = config.verification?.emailTTLms ?? 1000 * 60 * 60 * 24
	const passwordResetTTL = config.verification?.passwordResetTTLms ?? 1000 * 60 * 60

	// basic config validation
	if (!config.secret || config.secret.length < 16)
		throw new Error("authlite: secret must be set and at least 16 chars")
	if (ttlMs <= 0)
		throw new Error("authlite: session.ttlMs must be > 0")
	if (config.emailAndPassword?.enabled) {
		for (const k of ["createUser", "findUserByEmail"]) {
			if (!(adapter as any)[k])
				throw new Error(`authlite: credentials flow requires adapter.${k}`)
		}
	}

	async function getSession({ headers }: { headers: Headers }) {
		const cookieHeader = headers.get("cookie") ?? ""
		const raw = readCookie(cookieHeader, cookieName)
		if (!raw)
			return null
		const hashes = hashTokenAll(raw)

		if (cache) {
			for (const h of hashes) {
				const cached = await cache.getSession(h)
				if (cached && cached.session && Number(cached.session.expiresAt) > Date.now())
					return cached
			}
		}

		let s = null as any
		let matchedHash: null | string = null
		for (const h of hashes) {
			s = await adapter.findSessionByHash(h)
			if (s) {
				matchedHash = h
				break
			}
		}
		if (!s)
			return null
		if (Number(s.expiresAt) <= Date.now()) {
			if (matchedHash)
				await adapter.revokeSession(matchedHash).catch(() => {})
			if (cache && matchedHash)
				await cache.deleteSession(matchedHash).catch(() => {})
			return null
		}

		const user = await adapter.findUserById(s.userId)
		if (!user)
			return null

		// Sliding session: extend expiration if accessed after updateAgeMs
		const nowMs = Date.now()
		const expiresAtMs = Number(s.expiresAt)
		if (adapter.updateSessionExpiry && updateAgeMs > 0) {
			const ageRemaining = expiresAtMs - nowMs
			// If remaining lifetime is less than (ttl - updateAge), extend
			if (ageRemaining < ttlMs - updateAgeMs) {
				const newExpires = nowMs + ttlMs
				await adapter.updateSessionExpiry(hashes[0]!, newExpires).catch(() => {})
				if (cache) {
					await cache.setSession(hashes[0]!, { session: { ...s, expiresAt: new Date(newExpires) }, user }, ttlMs).catch(() => {})
				}
			}
		}

		const out = { session: s, user }
		if (cache) {
			const cacheKey = typeof s.token === "string" ? s.token : hashes[0]
			await cache.setSession(cacheKey, out, ttlMs)
		}
		return out
	}

	async function createSessionForUser(userId: string, meta?: any, headers?: Headers) {
		const raw = genRawToken()
		const hashed = hashToken(raw)
		const expiresAt = Date.now() + ttlMs
		const device = parseDeviceFromHeaders(headers)
		await adapter.createSession(userId, hashed, expiresAt, { ...meta, ...device })
		if (cache)
			await cache.setSession(hashed, { session: { expiresAt, userId }, user: null }, ttlMs)
		const cookie = buildSetCookie(cookieName, raw, expiresAt, { sameSite: "Lax" })
		return { cookie, expiresAt, token: raw }
	}

	async function revokeSession(rawToken: string) {
		const hashes = hashTokenAll(rawToken)
		for (const h of hashes) {
			await adapter.revokeSession(h).catch(() => {})
			if (cache)
				await cache.deleteSession(h).catch(() => {})
		}
	}

	async function revokeAllForUser(userId: string) {
		if (adapter.revokeAllForUser)
			await adapter.revokeAllForUser(userId).catch(() => {})
		if (cache && cache.revokeAllForUser)
			await cache.revokeAllForUser(userId).catch(() => {})
	}

	/* Credentials */
	async function signUp(opts: { email: string, password: string, name?: string }) {
		const parsed = v.parse(signupSchema, opts)
		// create user
		if (!adapter.createUser)
			throw new Error("adapter.createUser not implemented")
		const u = await adapter.createUser({ createdAt: new Date(Date.now()), email: parsed.email, id: createId(), name: parsed.name, updatedAt: new Date(Date.now()) })
		// store password in account (provider = 'credentials')
		const hashed = await hashPassword(parsed.password)
		if (!adapter.createAccount)
			throw new Error("adapter.createAccount not implemented")
		await adapter.createAccount({
			accountId: u.id,
			createdAt: new Date(Date.now()),
			id: createId(),
			password: hashed,
			providerId: "credentials",
			updatedAt: new Date(Date.now()),
			userId: u.id
		})
		const session = await createSessionForUser(u.id)
		return { session, user: u }
	}

	async function signIn(opts: { email: string, password: string }) {
		const parsed = v.parse(signinSchema, opts)
		if (!adapter.findUserByEmail)
			throw new Error("adapter.findUserByEmail not implemented")
		const u = await adapter.findUserByEmail(parsed.email)
		if (!u)
			throw new Error("invalid_credentials")
		// find account provider credentials
		if (!adapter.findAccountByProvider)
			throw new Error("adapter.findAccountByProvider not implemented")
		const acc = await adapter.findAccountByProvider("credentials", u.id)
		if (!acc || !acc.password)
			throw new Error("invalid_credentials")
		const ok = await verifyPassword(parsed.password, acc.password)
		if (!ok)
			throw new Error("invalid_credentials")
		const session = await createSessionForUser(u.id)
		return { session, user: u }
	}

	/* Email verification & password reset (credentials) */
	async function requestEmailVerification(opts: { userId: string }) {
		if (!adapter.createVerification)
			throw new Error("adapter.createVerification not implemented")
		const token = genRawToken()
		await adapter.createVerification({
			createdAt: new Date(Date.now()),
			expiresAt: new Date(Date.now() + verificationEmailTTL),
			id: createId(),
			identifier: `email_verify:${opts.userId}`,
			updatedAt: new Date(Date.now()),
			value: token
		})
		const user = await adapter.findUserById(opts.userId)
		if (user?.email && config.mailer?.sendVerificationEmail)
			await config.mailer.sendVerificationEmail(user.email, token).catch(() => {})
		return { token }
	}

	async function verifyEmail(opts: { token: string }) {
		if (!adapter.findVerificationByToken)
			throw new Error("adapter.findVerificationByToken not implemented")
		const row = await adapter.findVerificationByToken(opts.token)
		if (!row)
			throw new Error("invalid_token")
		if (Number(row.expiresAt) <= Date.now())
			throw new Error("token_expired")
		const userId = row.identifier.replace("email_verify:", "")
		if (!adapter.updateUser)
			throw new Error("adapter.updateUser not implemented")
		await adapter.updateUser(userId, { emailVerified: true as any })
		if (adapter.deleteVerification)
			await adapter.deleteVerification(row.id)
		return { ok: true as const }
	}

	async function requestPasswordReset(opts: { email: string }) {
		if (!adapter.findUserByEmail)
			throw new Error("adapter.findUserByEmail not implemented")
		const u = await adapter.findUserByEmail(opts.email)
		if (!u)
			return { ok: true as const } // do not leak
		if (!adapter.createVerification)
			throw new Error("adapter.createVerification not implemented")
		const token = genRawToken()
		await adapter.createVerification({
			createdAt: new Date(Date.now()),
			expiresAt: new Date(Date.now() + passwordResetTTL),
			id: createId(),
			identifier: `password_reset:${u.id}`,
			updatedAt: new Date(Date.now()),
			value: token
		})
		if (u.email && config.mailer?.sendPasswordResetEmail)
			await config.mailer.sendPasswordResetEmail(u.email, token).catch(() => {})
		return { ok: true as const }
	}

	async function resetPassword(opts: { token: string, newPassword: string }) {
		if (!adapter.findVerificationByToken)
			throw new Error("adapter.findVerificationByToken not implemented")
		const row = await adapter.findVerificationByToken(opts.token)
		if (!row)
			throw new Error("invalid_token")
		if (Number(row.expiresAt) <= Date.now())
			throw new Error("token_expired")
		const userId = row.identifier.replace("password_reset:", "")
		const hashed = await hashPassword(opts.newPassword)
		if (!adapter.updateAccountPassword)
			throw new Error("adapter.updateAccountPassword not implemented")
		await adapter.updateAccountPassword("credentials", userId, hashed)
		if (adapter.deleteVerification)
			await adapter.deleteVerification(row.id)
		return { ok: true as const }
	}

	/* OAuth flows */
	async function oauthRedirect(provider: "discord" | "github" | "microsoft", opts?: { redirectUri?: string, state?: string }) {
		const state = opts?.state ?? createId()
		const redirectUri = opts?.redirectUri ?? ""
		// create provider specific url
		if (provider === "github") {
			const cfg = config.socialProviders?.github
			if (!cfg)
				throw new Error("github not configured")
			const url = `https://github.com/login/oauth/authorize?client_id=${cfg.clientId}&scope=read:user user:email&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`
			return { url }
		}
		if (provider === "discord") {
			const cfg = config.socialProviders?.discord
			if (!cfg)
				throw new Error("discord not configured")
			const url = `https://discord.com/api/oauth2/authorize?client_id=${cfg.clientId}&scope=identify%20email&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`
			return { url }
		}
		if (provider === "microsoft") {
			const cfg = config.socialProviders?.microsoft
			if (!cfg)
				throw new Error("microsoft not configured")
			const url = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${cfg.clientId}&scope=openid%20email%20profile&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`
			return { url }
		}
		throw new Error("unsupported provider")
	}

	async function oauthCallback(provider: "discord" | "github" | "microsoft", opts: { code: string, state?: string, redirectUri?: string }) {
		let exchanged
		const redirectUri = opts.redirectUri ?? ""
		if (provider === "github") {
			if (!config.socialProviders?.github)
				throw new Error("github not configured")
			exchanged = await exchangeGithubCode(opts.code, redirectUri, config.socialProviders.github)
		}
		else if (provider === "discord") {
			if (!config.socialProviders?.discord)
				throw new Error("discord not configured")
			exchanged = await exchangeDiscordCode(opts.code, redirectUri, config.socialProviders.discord)
		}
		else if (provider === "microsoft") {
			if (!config.socialProviders?.microsoft)
				throw new Error("microsoft not configured")
			exchanged = await exchangeMicrosoftCode(opts.code, redirectUri, config.socialProviders.microsoft)
		}
		else {
			throw new Error("unsupported provider")
		}

		const profile = exchanged.profile
		// map profile to email & id
		const email = profile.email ?? profile.emails?.[0]?.value ?? null
		const providerAccountId = profile.id ?? profile.sub ?? profile.node_id ?? String(email)

		// find or create user
		let user = null
		if (email && adapter.findUserByEmail)
			user = await adapter.findUserByEmail(email)
		if (!user) {
			if (!adapter.createUser)
				throw new Error("adapter.createUser not implemented")
			user = await adapter.createUser({ createdAt: new Date(Date.now()), email: email ?? null, id: createId(), image: profile.avatar_url ?? profile.picture ?? null, name: profile.name ?? profile.login ?? null, updatedAt: new Date(Date.now()) })
		}

		// create/link account
		if (!adapter.findAccountByProvider)
			throw new Error("adapter.findAccountByProvider not implemented")
		const existing = await adapter.findAccountByProvider(provider, String(providerAccountId))
		if (!existing && adapter.createAccount) {
			await adapter.createAccount({
				accessToken: exchanged.access_token ?? null,
				accountId: String(providerAccountId),
				createdAt: new Date(Date.now()),
				id: createId(),
				providerId: provider,
				updatedAt: new Date(Date.now()),
				userId: user.id
			})
		}

		const session = await createSessionForUser(user.id)
		return { session, user }
	}

	async function rotateSession({ headers }: { headers: Headers }) {
		const cookieHeader = headers.get("cookie") ?? ""
		const raw = readCookie(cookieHeader, cookieName)
		if (!raw)
			return null
		const hashes = hashTokenAll(raw)
		let s = null as any
		let matchedHash: null | string = null
		for (const h of hashes) {
			s = await adapter.findSessionByHash(h)
			if (s) {
				matchedHash = h
				break
			}
		}
		if (!s)
			return null
		const newSession = await createSessionForUser(s.userId, undefined, headers)
		if (matchedHash) {
			await adapter.revokeSession(matchedHash).catch(() => {})
			if (cache)
				await cache.deleteSession(matchedHash).catch(() => {})
		}
		return newSession
	}

	async function listDevices(userId: string) {
		if (!adapter.findSessionsByUserId)
			return []
		const rows = await adapter.findSessionsByUserId(userId)
		return rows.map(r => ({ createdAt: r.createdAt, expiresAt: r.expiresAt, id: r.id, ipAddress: r.ipAddress ?? null, userAgent: r.userAgent ?? null }))
	}

	async function handler(req: Request): Promise<Response> {
		const url = new URL(req.url)
		const pathname = url.pathname
		const method = req.method.toUpperCase()
		const json = (data: any, status = 200, init: ResponseInit = {}) => new Response(JSON.stringify(data), { ...init, headers: { "content-type": "application/json", ...(init.headers ?? {}) }, status })
		const noContent = (init: ResponseInit = {}) => new Response(null, { ...init, status: init.status ?? 204 })
		const isSecure = url.protocol === "https:" || (req.headers.get("x-forwarded-proto") ?? "").toLowerCase().includes("https")

		try {
			// Basic request validation for state-changing routes
			const isWrite = method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE"
			if (isWrite) {
				const ct = req.headers.get("content-type") ?? ""
				const isOauthPath = pathname.includes("/oauth/")
				const csrfCfg = config.csrf ?? {}
				const originHeader = req.headers.get("origin") ?? ""
				const refererHeader = req.headers.get("referer") ?? ""

				// 1) Content-Type check unless globally disabled
				if (!csrfCfg.disableCSRFCheck) {
					if (!ct.toLowerCase().startsWith("application/json") && !isOauthPath)
						return json({ error: "unsupported_media_type" }, 415)
				}

				// 2) Origin/Referrer checks unless disabled
				if (!csrfCfg.disableCSRFCheck && !csrfCfg.disableOriginCheck) {
					// Build trusted hosts set: same-origin + configured
					const trustedHosts = new Set<string>([url.host])
					for (const t of csrfCfg.trustedOrigins ?? []) {
						try {
							const h = t.includes("://") ? new URL(t).host : t
							if (h)
								trustedHosts.add(h)
						}
						catch {}
					}
					let originHost = ""
					if (originHeader) {
						try {
							originHost = new URL(originHeader).host
						}
						catch {
							originHost = ""
						}
					}
					let refererHost = ""
					if (refererHeader) {
						try {
							refererHost = new URL(refererHeader).host
						}
						catch {
							refererHost = ""
						}
					}

					if (!isOauthPath) {
						// If Origin is present, it must be trusted
						if (originHost && !trustedHosts.has(originHost))
							return json({ error: "csrf_blocked" }, 403)
						// If Referer is present, it must be trusted
						if (refererHost && !trustedHosts.has(refererHost))
							return json({ error: "csrf_blocked" }, 403)
					}
				}
			}
			// Discover allowed methods for this path for better 405 handling
			let allowed: null | string[] = null
			// base routes
			if (pathname.endsWith("/session"))
				allowed = ["GET"]
			else if (pathname.endsWith("/session/rotate"))
				allowed = ["POST"]
			else if (pathname.endsWith("/signout"))
				allowed = ["POST"]
			else if (pathname.endsWith("/devices"))
				allowed = ["GET"]
			// credentials
			if (config.emailAndPassword?.enabled) {
				if (pathname.endsWith("/signup"))
					allowed = ["POST"]
				else if (pathname.endsWith("/signin"))
					allowed = ["POST"]
				else if (pathname.endsWith("/verify/request"))
					allowed = ["POST"]
				else if (pathname.endsWith("/verify"))
					allowed = ["POST"]
				else if (pathname.endsWith("/password/reset/request"))
					allowed = ["POST"]
				else if (pathname.endsWith("/password/reset"))
					allowed = ["POST"]
			}
			// oauth
			if (config.socialProviders) {
				if (/\/oauth\/(?:github|discord|microsoft)\/redirect$/.test(pathname))
					allowed = ["GET"]
				else if (/\/oauth\/(?:github|discord|microsoft)\/callback$/.test(pathname))
					allowed = ["GET"]
			}
			// Session info
			if (method === "GET" && pathname.endsWith("/session")) {
				const session = await getSession({ headers: req.headers })
				return json(session)
			}

			// Rotate session
			if (method === "POST" && pathname.endsWith("/session/rotate")) {
				const rotated = await rotateSession({ headers: req.headers })
				if (!rotated)
					return json({ error: "no_session", ok: false }, 401)
				const cookie = buildSetCookie(cookieName, rotated.token, rotated.expiresAt, { sameSite: "Lax", secure: isSecure })
				return json({ ok: true, session: { expiresAt: rotated.expiresAt } }, { headers: { "set-cookie": cookie } } as any)
			}

			// Sign out (revoke)
			if (method === "POST" && pathname.endsWith("/signout")) {
				const cookieHeader = req.headers.get("cookie") ?? ""
				const raw = readCookie(cookieHeader, cookieName)
				if (raw)
					await revokeSession(raw).catch(() => {})
				// clear cookie on client
				const expired = Date.now() - 1000 * 60 * 60 * 24
				const clearCookie = buildSetCookie(cookieName, "", expired, { sameSite: "Lax", secure: isSecure })
				return noContent({ headers: { "set-cookie": clearCookie } } as any)
			}

			// Credentials: signup/signin
			if (config.emailAndPassword?.enabled) {
				if (method === "POST" && pathname.endsWith("/signup")) {
					const body = await req.json().catch(() => ({}))
					const out = await signUp(body)
					const cookie = buildSetCookie(cookieName, out.session.token, out.session.expiresAt, { sameSite: "Lax", secure: isSecure })
					return json({ session: { expiresAt: out.session.expiresAt }, user: out.user }, { headers: { "set-cookie": cookie } } as any)
				}
				if (method === "POST" && pathname.endsWith("/signin")) {
					const body = await req.json().catch(() => ({}))
					const out = await signIn(body)
					const cookie = buildSetCookie(cookieName, out.session.token, out.session.expiresAt, { sameSite: "Lax", secure: isSecure })
					return json({ session: { expiresAt: out.session.expiresAt }, user: out.user }, { headers: { "set-cookie": cookie } } as any)
				}
				if (method === "POST" && pathname.endsWith("/verify/request")) {
					const body = await req.json().catch(() => ({}))
					const out = await requestEmailVerification(body)
					return json(out)
				}
				if (method === "POST" && pathname.endsWith("/verify")) {
					const body = await req.json().catch(() => ({}))
					const out = await verifyEmail(body)
					return json(out)
				}
				if (method === "POST" && pathname.endsWith("/password/reset/request")) {
					const body = await req.json().catch(() => ({}))
					const out = await requestPasswordReset(body)
					return json(out)
				}
				if (method === "POST" && pathname.endsWith("/password/reset")) {
					const body = await req.json().catch(() => ({}))
					const out = await resetPassword(body)
					return json(out)
				}
			}

			// OAuth
			if (config.socialProviders) {
				if (method === "GET" && /\/oauth\/(?:github|discord|microsoft)\/redirect$/.test(pathname)) {
					const match = pathname.match(/\/oauth\/(github|discord|microsoft)\/redirect$/)!
					const provider = (match?.[1] ?? "github") as "discord" | "github" | "microsoft"
					const redirectUri = url.searchParams.get("redirect_uri") ?? undefined
					const state = url.searchParams.get("state") ?? undefined
					const { url: redirectUrl } = await oauthRedirect(provider, { redirectUri, state })
					return new Response(null, { headers: { location: redirectUrl }, status: 302 })
				}
				if (method === "GET" && /\/oauth\/(?:github|discord|microsoft)\/callback$/.test(pathname)) {
					const match = pathname.match(/\/oauth\/(github|discord|microsoft)\/callback$/)!
					const provider = (match?.[1] ?? "github") as "discord" | "github" | "microsoft"
					const code = url.searchParams.get("code") ?? ""
					const state = url.searchParams.get("state") ?? undefined
					const redirectUri = url.searchParams.get("redirect_uri") ?? undefined
					const { session, user } = await oauthCallback(provider, { code, redirectUri, state })
					const cookie = buildSetCookie(cookieName, session.token, session.expiresAt, { sameSite: "Lax", secure: isSecure })
					return json({ session: { expiresAt: session.expiresAt }, user }, { headers: { "set-cookie": cookie } } as any)
				}
			}

			// Devices
			if (method === "GET" && pathname.endsWith("/devices")) {
				const sess = await getSession({ headers: req.headers })
				if (!sess)
					return json({ error: "unauthorized" }, 401)
				const userId = (sess as any).session?.userId ?? null
				if (!userId)
					return json({ error: "unauthorized" }, 401)
				const devices = await listDevices(String(userId))
				return json({ devices })
			}

			// If we matched a known path but method is not allowed
			if (allowed && !allowed.includes(method))
				return json({ error: "method_not_allowed" }, 405, { headers: { allow: allowed.join(", ") } })

			return json({ error: "not_found" }, 404)
		}
		catch (err: any) {
			const message = err?.message ?? "internal_error"
			const status = message === "invalid_credentials" || message === "invalid_token" ? 400 : message === "unauthorized" ? 401 : 500
			return json({ error: message }, status)
		}
	}

	const api: any = {
		createSession: async ({ headers, meta, userId }: { userId: string, meta?: any, headers?: Headers }) => createSessionForUser(userId, meta, headers),
		getSession,
		listDevices,
		revokeAllForUser,
		revokeSession,
		rotateSession
	}

	if (config.emailAndPassword?.enabled) {
		api.signUp = signUp
		api.signIn = signIn
		api.requestEmailVerification = requestEmailVerification
		api.verifyEmail = verifyEmail
		api.requestPasswordReset = requestPasswordReset
		api.resetPassword = resetPassword
	}

	if (config.socialProviders) {
		api.oauthRedirect = oauthRedirect
		api.oauthCallback = oauthCallback
	}

	return { api, handler }
}
