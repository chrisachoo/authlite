import type { RedisCacheAdapter } from "../types"

export function redisCacheAdapter(client: any): RedisCacheAdapter {
	return {
		async deleteSession(hash: string) {
			await client.del(`authlite:session:${hash}`)
		},
		async getSession(hash: string) {
			const v = await client.get(`authlite:session:${hash}`)
			return v ? JSON.parse(v) : null
		},
		async revokeAllForUser(userId: string) {
			// prefer indexed set if provided, fallback to scan
			const setKey = `authlite:user-sessions:${userId}`
			const members = await client.smembers?.(setKey)
			if (members?.length) {
				const pipeline = (client as any).multi?.() ?? (client as any).pipeline?.()
				if (pipeline) {
					for (const m of members)
						pipeline.del(`authlite:session:${m}`)
					await pipeline.exec()
				}
				return
			}
			const keys = await client.keys("authlite:session:*")
			if (!keys.length)
				return
			const pipeline = (client as any).multi?.() ?? (client as any).pipeline?.()
			for (const k of keys)
				pipeline.del(k)
			await pipeline.exec()
		},
		async setSession(hash: string, value: any, ttlMs: number) {
			await client.set(`authlite:session:${hash}`, JSON.stringify(value), "PX", ttlMs)
			if (value?.user?.id && client.sadd)
				await client.sadd(`authlite:user-sessions:${value.user.id}`, hash)
		}
	}
}
