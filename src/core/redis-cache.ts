import type { RedisCacheAdapter } from "../types"

export function redisCacheAdapter(client: any): RedisCacheAdapter {
	return {
		async deleteSession(hash: string) {
			await client.del(`zauth:session:${hash}`)
		},
		async getSession(hash: string) {
			const v = await client.get(`zauth:session:${hash}`)
			return v ? JSON.parse(v) : null
		},
		async revokeAllForUser(userId: string) {
			// prefer indexed set if provided, fallback to scan
			const setKey = `zauth:user-sessions:${userId}`
			const members = await client.smembers?.(setKey)
			if (members && members.length) {
				const pipeline = client.multi()
				for (const m of members)
					pipeline.del(`zauth:session:${m}`)
				await pipeline.exec()
				await client.del(setKey)
				return
			}
			const keys = await client.keys("zauth:session:*")
			if (!keys.length)
				return
			await client.del(...keys)
		},
		async setSession(hash: string, value: any, ttlMs: number) {
			if (ttlMs <= 0)
				return
			await client.set(`zauth:session:${hash}`, JSON.stringify(value), "PX", ttlMs)
			if (value?.user?.id && client.sadd)
				await client.sadd(`zauth:user-sessions:${value.user.id}`, hash)
		}
	}
}
