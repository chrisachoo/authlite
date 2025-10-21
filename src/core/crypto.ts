import crypto from "node:crypto"

let SECRETS: string[] = ["change_me"]

/** Set secret(s) for HMAC hashing. First is primary (used for new sessions). */
export function setSecret(secret: string | string[]) {
	if (Array.isArray(secret))
		SECRETS = secret.filter(Boolean)
	else
		SECRETS = [secret]
	if (SECRETS.length === 0)
		SECRETS = ["change_me"]
}

/** Generate a random session token */
export function genRawToken(): string {
	return crypto.randomBytes(32).toString("hex")
}

/** Hash a token for DB storage using HMAC-SHA256. */
export function hashToken(raw: string): string {
	return crypto.createHmac("sha256", SECRETS[0]).update(raw).digest("hex")
}

/** Compute token hashes with all configured secrets (for rotation overlap). */
export function hashTokenAll(raw: string): string[] {
	return SECRETS.map(s => crypto.createHmac("sha256", s).update(raw).digest("hex"))
}
