/** Extract device info from standard headers. */
export function parseDeviceFromHeaders(headers?: Headers) {
	const userAgent = headers?.get("user-agent") ?? null
	const forwarded = headers?.get("x-forwarded-for")
	const ip = forwarded?.split(",")[0]?.trim() || headers?.get("x-real-ip") || null
	return { ipAddress: ip, userAgent }
}
