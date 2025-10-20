import * as argon2 from "@node-rs/argon2"

export async function hashPassword(password: string): Promise<string> {
	return (argon2 as any).hash(password, { memoryCost: 2 ** 15, parallelism: 1, timeCost: 2 })
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
	return (argon2 as any).verify(hash, password)
}
