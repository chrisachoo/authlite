import { createId } from "@paralleldrive/cuid2"
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core"

export const user = sqliteTable("user", {
	createdAt: integer("created_at", { mode: "timestamp" }).$onUpdate(() => new Date()).notNull(),
	email: text("email").notNull().unique(),
	emailVerified: integer("email_verified", { mode: "boolean" }).default(false).notNull(),
	id: text("id").primaryKey().$defaultFn(() => createId()),
	image: text("image"),
	name: text("name").notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).$defaultFn(() => new Date()).$onUpdate(() => new Date()).notNull()
})

export const session = sqliteTable("session", {
	createdAt: integer("created_at", { mode: "timestamp" }).$onUpdate(() => new Date()).notNull(),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	id: text("id").primaryKey().$defaultFn(() => createId()),
	ipAddress: text("ip_address"), // The IP address of the device
	token: text("token").notNull().unique(), // The unique session token
	updatedAt: integer("updated_at", { mode: "timestamp" }).$onUpdate(() => new Date()).notNull(),
	userAgent: text("user_agent"), // The user agent information of the device
	userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" })
})

export const account = sqliteTable("account", {
	accessToken: text("access_token"), // The refresh token of the account. Returned by the provider
	accessTokenExpiresAt: integer("access_token_expires_at", { mode: "timestamp" }), // The access token of the account. Returned by the provider
	accountId: text("account_id").notNull(), // The ID of the account as provided by the SSO or equal to userId for credential accounts
	createdAt: integer("created_at", { mode: "timestamp" }).$onUpdate(() => new Date()).notNull(),
	id: text("id").primaryKey().$defaultFn(() => createId()),
	idToken: text("id_token"), // The ID token returned from the provider
	password: text("password"),
	providerId: text("provider_id").notNull(), // The ID of the provider
	refreshToken: text("refresh_token"), // The time when the access token expires
	refreshTokenExpiresAt: integer("refresh_token_expires_at", { mode: "timestamp" }), // The time when the refresh token expires
	scope: text("scope"), // The scope of the account. Returned by the provider
	updatedAt: integer("updated_at", { mode: "timestamp" }).$onUpdate(() => new Date()).notNull(),
	userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" })
})

export const verification = sqliteTable("verification", {
	createdAt: integer("created_at", { mode: "timestamp" }).$onUpdate(() => new Date()).notNull(),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	id: text("id").primaryKey().$defaultFn(() => createId()),
	identifier: text("identifier").notNull(), // The identifier for the verification request
	updatedAt: integer("updated_at", { mode: "timestamp" }).$onUpdate(() => new Date()).$onUpdate(() => new Date()).notNull(),
	value: text("value").notNull() // The value to be verified
})

export type User = typeof user.$inferSelect
export type Session = typeof session.$inferSelect
export type Account = typeof account.$inferSelect
export type Verification = typeof verification.$inferSelect
