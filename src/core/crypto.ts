import crypto from "node:crypto"

let SECRET = "change_me"

/** Set secret for HMAC hashing */
export function setSecret(secret: string) {
	SECRET = secret
}

/** Generate a random session token */
export function genRawToken(): string {
	return crypto.randomBytes(32).toString("hex")
}

/** Hash a token for DB storage using HMAC-SHA256. */
export function hashToken(raw: string): string {
	return crypto.createHmac("sha256", SECRET).update(raw).digest("hex")
}
