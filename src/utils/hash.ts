import crypto from "node:crypto"

let SECRET = "change_me"

export function setSecret(secret: string) {
	SECRET = secret
}

/**
 * Create a random session token (returned to the client).
 */
export function genRawToken(): string {
	return crypto.randomBytes(32).toString("hex")
}

/**
 * Hash the token for DB storage using HMAC-SHA256.
 * The secret is always provided by the consumer, not read from env.
 */
export function hashToken(raw: string): string {
	return crypto.createHmac("sha256", SECRET).update(raw).digest("hex")
}
