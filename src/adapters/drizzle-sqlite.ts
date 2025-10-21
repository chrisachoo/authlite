import type { DrizzleAdapter } from "../types"

import { and, eq } from "drizzle-orm"
import { account, session, user, verification } from "../db/schema"

// Keep adapter light by avoiding tight Drizzle typings to prevent cross-version type conflicts
export function drizzleSQLiteAdapter(db: any): DrizzleAdapter {
	return {
		async createAccount(a) {
			const [acc] = await db.insert(account).values(a as any).returning()
			return acc as any
		},
		async createSession(userId, tokenHash, expiresAt, meta) {
			const [sess] = await db
				.insert(session)
				.values({
					createdAt: new Date(Date.now()),
					expiresAt: new Date(expiresAt),
					ipAddress: meta?.ipAddress ?? null,
					token: tokenHash,
					updatedAt: new Date(Date.now()),
					userAgent: meta?.userAgent ?? null,
					userId
				} as any)
				.returning()
			return sess as any
		},
		async createUser(data) {
			const [u] = await db.insert(user).values(data as any).returning()
			return u as any
		},

		/* Verification */
		async createVerification(v) {
			const [row] = await db.insert(verification).values(v as any).returning()
			return row as any
		},
		async deleteVerification(id) {
			await db.delete(verification).where(eq(verification.id, id))
		},

		/* Accounts */
		async findAccountByProvider(providerId, providerAccountId) {
			const [acc] = await db
				.select()
				.from(account)
				.where(and(eq(account.providerId, providerId), eq(account.accountId, providerAccountId)))
			return (acc ?? null) as any
		},
		/* Sessions */
		async findSessionByHash(hash) {
			const [sess] = await db.select().from(session).where(eq(session.token, hash))
			return (sess ?? null) as any
		},
		async findSessionsByUserId(userId) {
			const rows = await db.select().from(session).where(eq(session.userId, userId))
			return rows as any
		},
		async findUserByEmail(email) {
			const [u] = await db.select().from(user).where(eq(user.email, email))
			return u ?? null
		},

		/* Users */
		async findUserById(id) {
			const [u] = await db.select().from(user).where(eq(user.id, id))
			return u ?? null
		},
		async findVerificationByToken(token) {
			const [row] = await db.select().from(verification).where(eq(verification.value, token))
			return (row ?? null) as any
		},
		async revokeAllForUser(userId) {
			await db.delete(session).where(eq(session.userId, userId))
		},

		async revokeSession(hash) {
			await db.delete(session).where(eq(session.token, hash))
		},
		async updateAccountPassword(providerId, accountId, passwordHash) {
			await db.update(account).set({ password: passwordHash }).where(and(eq(account.providerId, providerId), eq(account.accountId, accountId)))
		},
		async updateSessionExpiry(hash, newExpiresAtMs) {
			await db
				.update(session)
				.set({ expiresAt: new Date(newExpiresAtMs), updatedAt: new Date(Date.now()) })
				.where(eq(session.token, hash))
		},
		/* New helpers */
		async updateUser(id, data) {
			await db.update(user).set(data as any).where(eq(user.id, id))
		}
	}
}
