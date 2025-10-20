import type { Account, Session, User, Verification } from "./db/schema"

export type DrizzleAdapter = {
	findUserById: (id: string) => Promise<null | User>
	findUserByEmail?: (email: string) => Promise<null | User>
	findAccountByProvider?: (provider: string, providerId: string) => Promise<Account | null>
	createUser?: (data: Partial<User>) => Promise<User>
	createAccount?: (a: Partial<Account>) => Promise<Account>
	findSessionByHash: (hash: string) => Promise<null | Session>
	createSession: (userId: string, tokenHash: string, expiresAt: number, meta?: any) => Promise<Session>
	revokeSession: (hash: string) => Promise<void>
	revokeAllForUser?: (userId: string) => Promise<void>
	createVerification?: (v: Partial<Verification>) => Promise<Verification>
	findVerificationByToken?: (token: string) => Promise<null | Verification>
	deleteVerification?: (id: string) => Promise<void>
	// new optional capabilities
	updateUser?: (id: string, data: Partial<User>) => Promise<void>
	updateAccountPassword?: (providerId: string, accountId: string, passwordHash: string) => Promise<void>
	findSessionsByUserId?: (userId: string) => Promise<Session[]>
}

export type RedisCacheAdapter = {
	getSession: (hash: string) => Promise<{ user: null | User, session: null | Session } | null>
	setSession: (hash: string, value: any, ttlMs: number) => Promise<void>
	deleteSession: (hash: string) => Promise<void>
	revokeAllForUser?: (userId: string) => Promise<void>
}

export type ProviderConfig = {
	clientId: string
	clientSecret: string
}

/**
 * AuthConfig is the configuration for the auth system. It contains the configuration for the auth system.
 * It contains the configuration for the auth system. It is the configuration for the auth system.
 * It is the configuration for the auth system. It is the configuration for the auth system.
 *
 */
export type AuthConfig = {
	database: DrizzleAdapter
	session?: {
		ttlMs?: number
		cookieName?: string
		rotateEveryMs?: number
	}
	emailAndPassword?: { enabled: boolean }
	socialProviders?: Partial<{
		github: { clientId: string, clientSecret: string }
		microsoft: { clientId: string, clientSecret: string }
		discord: { clientId: string, clientSecret: string }
	}>
	cache?: null | RedisCacheAdapter
	secret: string
	mailer?: {
		sendVerificationEmail?: (to: string, token: string) => Promise<void>
		sendPasswordResetEmail?: (to: string, token: string) => Promise<void>
	}
	verification?: {
		emailTTLms?: number
		passwordResetTTLms?: number
	}
}

/**
 * AuthInstance is the main interface for the auth system. It contains the API for the auth system.
 * It is the main interface for the auth system. It is the main interface for the auth system.
 * It is the main interface for the auth system. It is the main interface for the auth system.
 *
 */
export type AuthInstance = {
	api: {
		getSession: (opts: { headers: Headers }) => Promise<{ user: User, session: Session } | null>
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
