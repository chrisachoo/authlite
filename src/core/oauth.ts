export type OAuthProviderConfig = { clientId: string, clientSecret: string }

export async function exchangeGithubCode(code: string, redirectUri: string, config: OAuthProviderConfig) {
	const params = new URLSearchParams({
		client_id: config.clientId,
		client_secret: config.clientSecret,
		code,
		redirect_uri: redirectUri
	})
	const tokenResp = await fetch(`https://github.com/login/oauth/access_token`, {
		body: params,
		headers: { Accept: "application/json" },
		method: "POST"
	})
	const tokenJson = await tokenResp.json()
	if (!tokenJson.access_token)
		throw new Error("github: no access token")
	const userResp = await fetch("https://api.github.com/user", { headers: { Authorization: `token ${tokenJson.access_token}` } })
	const profile = await userResp.json()
	return { access_token: tokenJson.access_token, profile }
}

export async function exchangeDiscordCode(code: string, redirectUri: string, config: OAuthProviderConfig) {
	const params = new URLSearchParams({
		client_id: config.clientId,
		client_secret: config.clientSecret,
		code,
		grant_type: "authorization_code",
		redirect_uri: redirectUri
	})
	const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
		body: params,
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		method: "POST"
	})
	const tokenJson = await tokenResp.json()
	if (!tokenJson.access_token)
		throw new Error("discord: no access token")
	const userResp = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: `Bearer ${tokenJson.access_token}` } })
	const profile = await userResp.json()
	return { access_token: tokenJson.access_token, profile }
}

export async function exchangeMicrosoftCode(code: string, redirectUri: string, config: OAuthProviderConfig) {
	const params = new URLSearchParams({
		client_id: config.clientId,
		client_secret: config.clientSecret,
		code,
		grant_type: "authorization_code",
		redirect_uri: redirectUri,
		scope: "openid email profile"
	})
	const tokenResp = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
		body: params,
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		method: "POST"
	})
	const tokenJson = await tokenResp.json()
	if (!tokenJson.access_token)
		throw new Error("microsoft: no access token")
	const userResp = await fetch("https://graph.microsoft.com/oidc/userinfo", { headers: { Authorization: `Bearer ${tokenJson.access_token}` } })
	const profile = await userResp.json()
	return { access_token: tokenJson.access_token, profile }
}
