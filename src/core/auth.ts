import type { AuthConfig, AuthInstance } from "../types"

import { createId } from "@paralleldrive/cuid2"
import * as v from "valibot"
import { buildSetCookie, readCookie } from "./cookies"
import { genRawToken, hashToken, setSecret } from "./crypto"
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
	const cookieName = config.session?.cookieName ?? "zauth"
	const _rotateEveryMs = config.session?.rotateEveryMs ?? 0
	const verificationEmailTTL = config.verification?.emailTTLms ?? 1000 * 60 * 60 * 24
	const passwordResetTTL = config.verification?.passwordResetTTLms ?? 1000 * 60 * 60

	// basic config validation
	if (!config.secret || config.secret.length < 16)
		throw new Error("zauth: secret must be set and at least 16 chars")
	if (ttlMs <= 0)
		throw new Error("zauth: session.ttlMs must be > 0")
	if (config.emailAndPassword?.enabled) {
		const need = ["createUser", "createAccount", "findUserByEmail", "findAccountByProvider"] as const
		for (const k of need) {
			if (!(adapter as any)[k])
				throw new Error(`zauth: credentials flow requires adapter.${k}`)
		}
	}

	async function getSession({ headers }: { headers: Headers }) {
		const cookieHeader = headers.get("cookie") ?? ""
		const raw = readCookie(cookieHeader, cookieName)
		if (!raw)
			return null
		const hashed = hashToken(raw)

		if (cache) {
			const cached = await cache.getSession(hashed)
			if (cached && cached.session && Number(cached.session.expiresAt) > Date.now())
				return cached
		}

		const s = await adapter.findSessionByHash(hashed)
		if (!s)
			return null
		if (Number(s.expiresAt) <= Date.now()) {
			await adapter.revokeSession(hashed).catch(() => {})
			if (cache)
				await cache.deleteSession(hashed).catch(() => {})
			return null
		}

		const user = await adapter.findUserById(s.userId)
		if (!user)
			return null

		const out = { session: s, user }
		if (cache)
			await cache.setSession(hashed, out, ttlMs)
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
		const hash = hashToken(rawToken)
		await adapter.revokeSession(hash)
		if (cache)
			await cache.deleteSession(hash).catch(() => {})
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
		const hashed = hashToken(raw)
		const s = await adapter.findSessionByHash(hashed)
		if (!s)
			return null
		const newSession = await createSessionForUser(s.userId, undefined, headers)
		await revokeSession(raw).catch(() => {})
		return newSession
	}

	async function listDevices(userId: string) {
		if (!adapter.findSessionsByUserId)
			return []
		const rows = await adapter.findSessionsByUserId(userId)
		return rows.map(r => ({ createdAt: r.createdAt, expiresAt: r.expiresAt, id: r.id, ipAddress: r.ipAddress ?? null, userAgent: r.userAgent ?? null }))
	}

	async function handler(_req: Request): Promise<Response> {
		return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" }, status: 200 })
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
