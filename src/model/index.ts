export type { Account, Session, User, Verification } from "../db/schema"

export type DrizzleAdapter = {
	findUserById: (id: string) => Promise<import("../db/schema").User | null>
	findUserByEmail?: (email: string) => Promise<import("../db/schema").User | null>
	findAccountByProvider?: (provider: string, providerId: string) => Promise<import("../db/schema").Account | null>
	createUser?: (data: Partial<import("../db/schema").User>) => Promise<import("../db/schema").User>
	createAccount?: (a: Partial<import("../db/schema").Account>) => Promise<import("../db/schema").Account>
	findSessionByHash: (hash: string) => Promise<import("../db/schema").Session | null>
	createSession: (userId: string, tokenHash: string, expiresAt: number, meta?: any) => Promise<import("../db/schema").Session>
	revokeSession: (hash: string) => Promise<void>
	revokeAllForUser?: (userId: string) => Promise<void>
	createVerification?: (v: Partial<import("../db/schema").Verification>) => Promise<import("../db/schema").Verification>
	findVerificationByToken?: (token: string) => Promise<import("../db/schema").Verification | null>
	deleteVerification?: (id: string) => Promise<void>
	// new optional capabilities
	updateUser?: (id: string, data: Partial<import("../db/schema").User>) => Promise<void>
	updateAccountPassword?: (providerId: string, accountId: string, passwordHash: string) => Promise<void>
	findSessionsByUserId?: (userId: string) => Promise<Array<import("../db/schema").Session>>
	updateSessionExpiry?: (hash: string, newExpiresAtMs: number) => Promise<void>
}

export type RedisCacheAdapter = {
	getSession: (hash: string) => Promise<{ user: import("../db/schema").User | null, session: import("../db/schema").Session | null } | null>
	setSession: (hash: string, value: any, ttlMs: number) => Promise<void>
	deleteSession: (hash: string) => Promise<void>
	revokeAllForUser?: (userId: string) => Promise<void>
}

export type ProviderConfig = {
	clientId: string
	clientSecret: string
}

export type AuthConfig = {
	database: DrizzleAdapter
	session?: {
		ttlMs?: number
		cookieName?: string
		rotateEveryMs?: number
		/** Sliding session window: extend expiry when accessed after this age */
		updateAgeMs?: number
	}
	emailAndPassword?: { enabled: boolean }
	socialProviders?: Partial<{
		github: { clientId: string, clientSecret: string }
		microsoft: { clientId: string, clientSecret: string }
		discord: { clientId: string, clientSecret: string }
	}>
	cache?: null | RedisCacheAdapter
	secret: string | string[]
	mailer?: {
		sendVerificationEmail?: (to: string, token: string) => Promise<void>
		sendPasswordResetEmail?: (to: string, token: string) => Promise<void>
	}
	verification?: {
		emailTTLms?: number
		passwordResetTTLms?: number
	}
	csrf?: {
		/** Disable all CSRF checks (not recommended) */
		disableCSRFCheck?: boolean
		/** Disable origin/referrer checks only */
		disableOriginCheck?: boolean
		/** Trusted origins (full URLs or hostnames) allowed to perform writes */
		trustedOrigins?: string[]
	}
}

export type AuthInstance = {
	api: {
		getSession: (opts: { headers: Headers }) => Promise<{ user: import("../db/schema").User, session: import("../db/schema").Session } | null>
		createSession: (opts: { userId: string, meta?: any, headers?: Headers }) => Promise<{ token: string, cookie: string, expiresAt: number }>
		revokeSession: (token: string) => Promise<void>
		revokeAllForUser: (userId: string) => Promise<void>
		// credential flows
		signUp?: (opts: { email: string, password: string, name?: string }) => Promise<{ user: any, session: any }>
		signIn?: (opts: { email: string, password: string }) => Promise<{ user: any, session: any }>
		// email verification / password reset (credentials only)
		requestEmailVerification?: (opts: { userId: string }) => Promise<{ token: string }>
		verifyEmail?: (opts: { token: string }) => Promise<{ ok: true }>
		requestPasswordReset?: (opts: { email: string }) => Promise<{ ok: true }>
		resetPassword?: (opts: { token: string, newPassword: string }) => Promise<{ ok: true }>
		// oauth
		oauthRedirect?: (provider: "discord" | "github" | "microsoft", opts?: { redirectUri?: string, state?: string }) => Promise<{ url: string }>
		oauthCallback?: (provider: "discord" | "github" | "microsoft", opts: { code: string, state?: string, redirectUri?: string }) => Promise<{ user: any, session: any }>
		// sessions & devices
		rotateSession: (opts: { headers: Headers }) => Promise<{ token: string, cookie: string, expiresAt: number } | null>
		listDevices: (userId: string) => Promise<Array<{ id: string, createdAt: Date, expiresAt: Date, userAgent: null | string, ipAddress: null | string }>>
	}
	handler: (req: Request) => Promise<Response>
}
