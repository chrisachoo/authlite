import { describe, expect, it } from "vitest"
import { createAuth } from "../src/index"

function createMemoryAdapter() {
	const accounts = new Map<string, any>()
	const sessions = new Map<string, any>()
	const users = new Map<string, any>()
	const verifications = new Map<string, any>()

	return {
		createAccount: async (a: any) => {
			const acc = {
				accessToken: null,
				accessTokenExpiresAt: null,
				accountId: a.accountId ?? "",
				createdAt: new Date(),
				id: String(Math.random()),
				idToken: null,
				password: a.password ?? null,
				providerId: a.providerId ?? "",
				refreshToken: null,
				refreshTokenExpiresAt: null,
				scope: null,
				updatedAt: new Date(),
				userId: a.userId ?? ""
			}
			accounts.set(`${acc.providerId}:${acc.accountId}`, acc)
			return acc
		},
		createSession: async (userId: string, tokenHash: string, expiresAt: number) => {
			const s = {
				createdAt: new Date(),
				expiresAt: new Date(expiresAt),
				id: String(Math.random()),
				ipAddress: null,
				token: tokenHash,
				updatedAt: new Date(),
				userAgent: null,
				userId
			}
			sessions.set(tokenHash, s)
			return s
		},
		createUser: async (data: any) => {
			const u = {
				createdAt: new Date(),
				email: data.email ?? "",
				emailVerified: false,
				id: data.id ?? String(Math.random()),
				image: null,
				name: data.name ?? "",
				updatedAt: new Date()
			}
			users.set(u.id, u)
			return u
		},
		createVerification: async (v: any) => {
			const id = String(Math.random())
			const row = {
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + 60000),
				id,
				identifier: v?.identifier ?? "",
				updatedAt: new Date(),
				value: v?.value ?? ""
			}
			verifications.set(id, row)
			return row
		},
		deleteVerification: async (id: string) => {
			verifications.delete(id)
		},
		findAccountByProvider: async (provider: string, providerId: string) => accounts.get(`${provider}:${providerId}`) ?? null,
		findSessionByHash: async (hash: string) => sessions.get(hash) ?? null,
		findUserByEmail: async (email: string) => Array.from(users.values()).find(u => u.email === email) ?? null,
		findUserById: async (id: string) => users.get(id) ?? null,
		revokeAllForUser: async (userId: string) => {
			for (const [k, v] of sessions) {
				if (v.userId === userId)
					sessions.delete(k)
			}
		},
		revokeSession: async (hash: string) => {
			sessions.delete(hash)
		}
	}
}

describe("auth core", () => {
	it("createAuth minimal lifecycle", async () => {
		const database = createMemoryAdapter()
		const auth = createAuth({
			database,
			emailAndPassword: { enabled: true },
			secret: "test_secret_very_secure_123",
			session: { cookieName: "authlite", ttlMs: 1000 }
		})

		const { session, user } = await auth.api.signUp!({ email: "a@b.com", name: "A", password: "password123" })
		expect(user.id).toBeTruthy()
		expect(session.token).toBeTruthy()

		const got = await auth.api.getSession({ headers: new Headers({ cookie: `authlite=${session.token}` }) })
		expect(got).toBeTruthy()
	})
})
