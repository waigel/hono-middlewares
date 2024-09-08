import { Hono } from "hono";
import { env } from "hono/adapter";
import { jwks } from "../../../src/index";

const AUTH_DOMAIN = "https://hono-middlewares-jwks.family-waigel.workers.dev";

type Bindings = {
	JWKS_CACHE_NAMESPACE: KVNamespace;
};

const app = new Hono<{ Bindings: Bindings }>();

app.get("/.well-known/openid-configuration", async (ctx) => {
	return ctx.json({
		jwks_uri: `${AUTH_DOMAIN}/.well-known/jwks.json`,
	});
});

app.get("/.well-known/jwks.json", async (ctx) => {
	console.log("JWKS - was fetched");
	return ctx.json({
		keys: [
			{
				kty: "RSA",
				n: "0TkC_zGLwC1IACkf3scyi3RLJRmFFYUQvrQ33LoIb2lVgNWxyhRsfp9XwaHYrRT1ZRJv0U9xTRDAWWlTOMP3cWYFrJVvnPODWZdFIClNqDhbzRUXz5VBmNa2cGwCB_LLp37FrRAcJ7NJAeCxdNUW93gZ6ONwW_WAqxvp4jK2a7N5ZvQKareyBd7DZzBhHiMsqmAQhBMXRjMESOBYtxVdQonvSu2YziUemc8hUMF0cKf-xE-RhasL0oMpZE3d7hk9Qw_XaSQFPlcmUUKkfgnxRoLXDYunDRtStzKsBHlMpSbWcD0ZODzxPWf3HP5sh4UzZ2Z0_Ht_OejSAcup5_NdhQ",
				e: "AQAB",
				ext: true,
				kid: "23ff683cd234a917fa725b",
				alg: "RS256",
				use: "sig",
			},
		],
	});
});

app.get("/", async (ctx) => {
	console.log("HANDLER - environment", env(ctx));
	const token =
		"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";
	const result = await app.request("/authenticated", {
		headers: {
			Authorization: `Bearer ${token}`,
		},
	});
	if (result.ok) {
		return ctx.json((await result.json()) as string);
	}
	return ctx.text((await result.text()) as string);
});

app.get("/invalidtoken", async (ctx) => {
	const token =
		"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5TdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";
	const result = await app.request("/authenticated", {
		headers: {
			Authorization: `Bearer ${token}`,
		},
	});
	if (result.ok) {
		return ctx.json((await result.json()) as string);
	}
	return ctx.text((await result.text()) as string);
});

app.use("*", jwks({ domain: AUTH_DOMAIN }));

app.get("/authenticated", async (ctx) => {
	return ctx.json({ message: "Authenticated" });
});

export default app;
