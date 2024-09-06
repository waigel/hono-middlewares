import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { jwks } from ".";

type Env = {
	Variables: {
		// biome-ignore lint/suspicious/noExplicitAny: <explanation>
		jwtPayload: any;
		sub?: string;
	};
};

const server = setupServer(
	http.get(
		"http://localhost:8000/.well-known/openid-configuration",
		async () => {
			return HttpResponse.json({
				jwks_uri: "http://localhost:8000/.well-known/jwks.json",
			});
		},
	),
	http.get("http://localhost:8000/.well-known/jwks.json", async () => {
		return HttpResponse.json({
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
	}),
);

const jwksUrl = "http://localhost:8000";

describe("JWKS", () => {
	beforeAll(() => server.listen());

	afterAll(() => server.close());

	describe("Credentials in header", () => {
		let handlerExecuted: boolean;

		beforeEach(() => {
			handlerExecuted = false;
			server.resetHandlers();
		});

		const app = new Hono<Env>();

		app.use("/auth/*", jwks({ domain: jwksUrl }));
		app.use(
			"/auth-sub/*",
			jwks({ domain: jwksUrl, subjectToSubContextVariable: "message" }),
		);
		app.use("/auth-unicode/*", jwks({ domain: jwksUrl }));
		app.use("/nested/*", async (c, next) => {
			const auth = jwks({ domain: jwksUrl });
			return auth(c, next);
		});

		app.get("/auth/*", (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});
		app.get("/auth-sub/*", (c) => {
			handlerExecuted = true;
			const sub = c.get("sub");
			return c.json({ sub });
		});
		app.get("/auth-unicode/*", (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});
		app.get("/nested/*", (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});

		it("Should not authorize", async () => {
			const req = new Request("http://localhost/auth/a");
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(await res.text()).toBe("Unauthorized");
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should authorize", async () => {
			const credential =
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";
			const req = new Request("http://localhost/auth/a");
			req.headers.set("Authorization", `Bearer ${credential}`);
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(handlerExecuted).toBeTruthy();
		});

		it("should set the 'sub' context variable", async () => {
			const credential =
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";
			const req = new Request("http://localhost/auth-sub/a");
			req.headers.set("Authorization", `Bearer ${credential}`);
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({
				sub: "hello world",
			});
			expect(handlerExecuted).toBeTruthy();
		});

		it("Should authorize Unicode", async () => {
			const credential =
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";

			const req = new Request("http://localhost/auth-unicode/a");
			req.headers.set("Authorization", `Basic ${credential}`);
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(handlerExecuted).toBeTruthy();
		});

		it("Should not authorize Unicode", async () => {
			const invalidToken =
				"ssyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.B54pAqIiLbu170tGQ1rY06Twv__0qSHTA0ioQPIOvFE";

			const url = "http://localhost/auth-unicode/a";
			const req = new Request(url);
			req.headers.set("Authorization", `Basic ${invalidToken}`);
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(res.headers.get("www-authenticate")).toEqual(
				`Bearer realm="${url}",error="invalid_token",error_description="token verification failure"`,
			);
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should not authorize", async () => {
			const invalid_token = "invalid token";
			const url = "http://localhost/auth/a";
			const req = new Request(url);
			req.headers.set("Authorization", `Bearer ${invalid_token}`);
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(res.headers.get("www-authenticate")).toEqual(
				`Bearer realm="${url}",error="invalid_request",error_description="invalid credentials structure"`,
			);
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should not authorize - nested", async () => {
			const req = new Request("http://localhost/nested/a");
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(await res.text()).toBe("Unauthorized");
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should authorize - nested", async () => {
			const credential =
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";
			const req = new Request("http://localhost/nested/a");
			req.headers.set("Authorization", `Bearer ${credential}`);
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(handlerExecuted).toBeTruthy();
		});
	});

	describe("Credentials in cookie", () => {
		let handlerExecuted: boolean;

		beforeEach(() => {
			handlerExecuted = false;
			server.resetHandlers();
		});

		const app = new Hono<Env>();

		app.use("/auth/*", jwks({ domain: jwksUrl, cookie: "access_token" }));
		app.use(
			"/auth-unicode/*",
			jwks({ domain: jwksUrl, cookie: "access_token" }),
		);

		app.get("/auth/*", (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});
		app.get("/auth-unicode/*", (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});

		it("Should not authorize", async () => {
			const req = new Request("http://localhost/auth/a");
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(await res.text()).toBe("Unauthorized");
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should authorize", async () => {
			const url = "http://localhost/auth/a";
			const credential =
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";
			const req = new Request(url, {
				headers: new Headers({
					Cookie: `access_token=${credential}`,
				}),
			});
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(res.status).toBe(200);
			expect(handlerExecuted).toBeTruthy();
		});

		it("Should authorize Unicode", async () => {
			const credential =
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";

			const req = new Request("http://localhost/auth-unicode/a", {
				headers: new Headers({
					Cookie: `access_token=${credential}`,
				}),
			});
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(handlerExecuted).toBeTruthy();
		});

		it("Should not authorize Unicode", async () => {
			const invalidToken =
				"ssyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.B54pAqIiLbu170tGQ1rY06Twv__0qSHTA0ioQPIOvFE";

			const url = "http://localhost/auth-unicode/a";
			const req = new Request(url);
			req.headers.set("Cookie", `access_token=${invalidToken}`);
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(res.headers.get("www-authenticate")).toEqual(
				`Bearer realm="${url}",error="invalid_token",error_description="token verification failure"`,
			);
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should not authorize", async () => {
			const invalidToken = "invalid token";
			const url = "http://localhost/auth/a";
			const req = new Request(url);
			req.headers.set("Cookie", `access_token=${invalidToken}`);
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(res.headers.get("www-authenticate")).toEqual(
				`Bearer realm="${url}",error="invalid_token",error_description="token verification failure"`,
			);
			expect(handlerExecuted).toBeFalsy();
		});
	});

	describe("Error handling with `cause`", () => {
		const app = new Hono<Env>();

		app.use("/auth/*", jwks({ domain: jwksUrl }));
		app.get("/auth/*", (c) => c.text("Authorized"));

		app.onError((e, c) => {
			if (e instanceof HTTPException && e.cause instanceof Error) {
				return c.json({ name: e.cause.name, message: e.cause.message }, 401);
			}
			return c.text(e.message, 401);
		});

		it("Should not authorize", async () => {
			const credential = "abc.def.ghi";
			const req = new Request("http://localhost/auth");
			req.headers.set("Authorization", `Bearer ${credential}`);
			const res = await app.request(req);
			expect(res.status).toBe(401);
			expect(await res.json()).toEqual({
				name: "JwtTokenInvalid",
				message: `invalid JWT token: ${credential}`,
			});
		});
	});

	describe("Credentials in signed cookie with prefix Options", () => {
		let handlerExecuted: boolean;

		beforeEach(() => {
			handlerExecuted = false;
			server.resetHandlers();
		});

		const app = new Hono<Env>();

		app.use(
			"/auth/*",
			jwks({
				domain: jwksUrl,
				cookie: {
					key: "cookie_name",
					secret: "cookie_secret",
					prefixOptions: "host",
				},
			}),
		);

		app.get("/auth/*", async (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});

		it("Should not authorize", async () => {
			const req = new Request("http://localhost/auth/a");
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(await res.text()).toBe("Unauthorized");
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should authorize", async () => {
			const url = "http://localhost/auth/a";
			const req = new Request(url, {
				headers: new Headers({
					Cookie:
						"__Host-cookie_name=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew.kfjQ5yW3QVkhT3%2BVpo%2BI9O1TCkDx82f4XnhIEQYwNsY%3D; Path=/",
				}),
			});
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(handlerExecuted).toBeTruthy();
		});
	});

	describe("Credentials in signed cookie without prefix Options", () => {
		let handlerExecuted: boolean;

		beforeEach(() => {
			handlerExecuted = false;
			server.resetHandlers();
		});

		const app = new Hono<Env>();

		app.use(
			"/auth/*",
			jwks({
				domain: jwksUrl,
				cookie: {
					key: "cookie_name",
					secret: "cookie_secret",
				},
			}),
		);

		app.get("/auth/*", async (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});

		it("Should not authorize", async () => {
			const req = new Request("http://localhost/auth/a");
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(await res.text()).toBe("Unauthorized");
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should authorize", async () => {
			const url = "http://localhost/auth/a";
			const req = new Request(url, {
				headers: new Headers({
					Cookie:
						"cookie_name=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew.kfjQ5yW3QVkhT3%2BVpo%2BI9O1TCkDx82f4XnhIEQYwNsY%3D; Path=/",
				}),
			});
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(handlerExecuted).toBeTruthy();
		});
	});

	describe("Credentials in cookie object with prefix Options", () => {
		let handlerExecuted: boolean;

		beforeEach(() => {
			handlerExecuted = false;
			server.resetHandlers();
		});

		const app = new Hono<Env>();

		app.use(
			"/auth/*",
			jwks({
				domain: jwksUrl,
				cookie: {
					key: "cookie_name",
					prefixOptions: "host",
				},
			}),
		);

		app.get("/auth/*", async (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});

		it("Should not authorize", async () => {
			const req = new Request("http://localhost/auth/a");
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(await res.text()).toBe("Unauthorized");
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should authorize", async () => {
			const url = "http://localhost/auth/a";
			const req = new Request(url, {
				headers: new Headers({
					Cookie:
						"__Host-cookie_name=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew",
				}),
			});
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(handlerExecuted).toBeTruthy();
		});
	});

	describe("Credentials in cookie object without prefix Options", () => {
		let handlerExecuted: boolean;

		beforeEach(() => {
			handlerExecuted = false;
			server.resetHandlers();
		});

		const app = new Hono<Env>();

		app.use(
			"/auth/*",
			jwks({
				domain: jwksUrl,
				cookie: {
					key: "cookie_name",
				},
			}),
		);

		app.get("/auth/*", async (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});

		it("Should not authorize", async () => {
			const req = new Request("http://localhost/auth/a");
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(401);
			expect(await res.text()).toBe("Unauthorized");
			expect(handlerExecuted).toBeFalsy();
		});

		it("Should authorize", async () => {
			const url = "http://localhost/auth/a";
			const req = new Request(url, {
				headers: new Headers({
					Cookie:
						"cookie_name=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew",
				}),
			});
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(await res.json()).toEqual({ message: "hello world" });
			expect(handlerExecuted).toBeTruthy();
		});
	});

	describe("Cache options for JWKS", () => {
		let handlerExecuted: boolean;

		beforeEach(() => {
			handlerExecuted = false;
			server.resetHandlers();
		});

		const app = new Hono<Env>();

		app.use(
			"/auth/*",
			jwks({
				domain: jwksUrl,
			}),
		);

		app.use(
			"/auth/disable-cache/*",
			jwks({
				domain: jwksUrl,
				getJwksOptions: {
					max: 1,
					ttl: 1,
					timeout: 1,
				},
			}),
		);

		app.get("/auth/*", async (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});

		app.get("/auth/disable-cache/*", async (c) => {
			handlerExecuted = true;
			const payload = c.get("jwtPayload");
			return c.json(payload);
		});

		it("Should not fetch JWKS again when cache is enabled", async () => {
			const dispatchRequest = vi.fn();
			server.events.on("request:start", dispatchRequest);

			const credential =
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";
			const req = new Request("http://localhost/auth/a");
			req.headers.set("Authorization", `Bearer ${credential}`);

			// first request
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(handlerExecuted).toBeTruthy();

			// reset handler execution
			handlerExecuted = false;

			// second request
			const res2 = await app.request(req);
			expect(res2).not.toBeNull();
			expect(res2.status).toBe(200);
			expect(handlerExecuted).toBeTruthy();

			//check that the jwks_uri was only requested once
			expect(dispatchRequest).toHaveBeenCalledTimes(1);
		});

		it("Should fetch JWKS again when cache is disabled", async () => {
			const dispatchRequest = vi.fn();
			server.events.on("request:start", dispatchRequest);

			const credential =
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzZmY2ODNjZDIzNGE5MTdmYTcyNWIifQ.eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ.RSfeJmhhbv0DONbwml-V0TwHLjKHaaON3-keyjacD1-RlvGiXpK2uerkrtgz-on4qLPJlh6c1qe6VCnatYlGeFQ3QQJIqXM-Q2ZNS0kNHz4oeJWdzvPRTM-gUmMb3rmw2EK7TlBAg2mVRCfqNW9jdwnfbd56JmfwTT7rYCVQKzZbgUNLFfB0lHtA86AUWZmpc-es3l-b1mxYLsdQroGS1cpCUsRe7et2nCmJSu3qJybKvYC4gDd8mmMEii-Fej69Esxl4UWgcEwD2cqViyvpClKtrhcgA5Nf0a624NUBVcS-7nHZNX1TJPTbnx6LQThBx7A7GU1b_XB0ig0wZ8Zpew";
			const req = new Request("http://localhost/auth/disable-cache/a");
			req.headers.set("Authorization", `Bearer ${credential}`);

			// first request
			const res = await app.request(req);
			expect(res).not.toBeNull();
			expect(res.status).toBe(200);
			expect(handlerExecuted).toBeTruthy();

			// reset handler execution
			handlerExecuted = false;

			await new Promise((resolve) => setTimeout(resolve, 2));
			// second request
			const res2 = await app.request(req);
			expect(res2).not.toBeNull();
			expect(res2.status).toBe(200);
			expect(handlerExecuted).toBeTruthy();

			//check that the jwks_uri was only requested once
			expect(dispatchRequest).toHaveBeenCalledTimes(2);
		});
	});
});
