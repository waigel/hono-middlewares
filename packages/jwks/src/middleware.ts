import buildGetJwks, {
	type GetJwks,
	type GetJwksOptions,
	type GetPublicKeyOptions,
} from "@waigel/get-jwks";
import type { Context, MiddlewareHandler } from "hono";
import { getRuntimeKey } from "hono/adapter";
import { getCookie, getSignedCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";
import { HTTPException } from "hono/http-exception";
import type { CookiePrefixOptions } from "hono/utils/cookie";
import { Jwt } from "hono/utils/jwt";

type Variables = {
	// biome-ignore lint/suspicious/noExplicitAny: <explanation>
	jwtPayload: any;
	sub: string | undefined | never | unknown;
};

interface JwksOptions extends GetJwksOptions {
	/** Max items to hold in cache. Defaults to 100. */
	max: GetJwksOptions["max"];
	/** Milliseconds an item will remain in cache. Defaults to 60s. */
	ttl: GetJwksOptions["ttl"];
	/** Specifies how long it should wait to retrieve a JWK before it fails. The time is set in milliseconds. Defaults to 5s.  */
	timeout: GetJwksOptions["timeout"];
	/** Array of allowed issuers. By default all issuers are allowed. */
	issuersWhitelist: GetJwksOptions["issuersWhitelist"];
	/**
	 * Indicates if the Provider Configuration Information is used to automatically get the jwks_uri from the OpenID Provider Discovery Endpoint.
	 * This endpoint is exposing the Provider Metadata.
	 * With this flag set to true the domain will be treated as the OpenID Issuer which is the iss property in the token.
	 * Defaults to false. Ignored if jwksPath is specified.
	 * */
	providerDiscovery: GetJwksOptions["providerDiscovery"];
	/** Specify a relative path to the jwks_uri. Example /otherdir/jwks.json. Takes precedence over providerDiscovery. Optional. */
	jwksPath: GetJwksOptions["jwksPath"];
}

interface MiddlewareOptions {
	domain: string;
	getJwksOptions?: Partial<JwksOptions>;
	cookie?:
		| string
		| {
				key: string;
				secret?: string | BufferSource;
				prefixOptions?: CookiePrefixOptions;
		  };

	kvNamespace?: string;
	expirationTtl?: number;

	/**
	 * Set the JWT subject claim to a context variable.
	 *
	 * ctx.set("sub", payload.claim.subjectToContextVariable);
	 * @default "sub" - The subject claim is set to the "sub" context variable.
	 */
	subjectToSubContextVariable?: string;
}

/**
 * JWT Payload
 */
export type JWTPayload = {
	[key: string]: unknown;
	/**
	 * The token is checked to ensure it has not expired.
	 */
	exp?: number;
	/**
	 * The token is checked to ensure it is not being used before a specified time.
	 */
	nbf?: number;
	/**
	 * The token is checked to ensure it is not issued in the future.
	 */
	iat?: number;
	/**
	 * The subject of the token. This is usually the identifier of the user the token represents.
	 */
	sub?: string;
};

export function createJWKSMiddleware<T extends JWTPayload>(
	options: MiddlewareOptions,
): MiddlewareHandler {
	const {
		domain,
		getJwksOptions,
		subjectToSubContextVariable = "sub",
		expirationTtl = 60,
	} = options;

	const getJwks = buildGetJwks({
		...getJwksOptions,
		issuersWhitelist: [...(getJwksOptions?.issuersWhitelist ?? []), domain],
	});

	return createMiddleware<{ Variables: Variables }>(async (ctx, next) => {
		// biome-ignore lint/suspicious/noExplicitAny: <explanation>
		const kvNamespace = (ctx.env as any)?.[
			options.kvNamespace ?? "JWKS_CACHE_NAMESPACE"
		] as KVNamespace | undefined;
		const token = await getAuthorizationToken(options, ctx);

		let payload: T | undefined;
		let cause: unknown;
		try {
			const { header } = Jwt.decode(token);
			const publicKey = await getPublicKey(
				getJwks,
				{
					// biome-ignore lint/suspicious/noExplicitAny: The header is not typed in the jwt library
					kid: (header as any)?.kid,
					alg: header?.alg,
					domain,
				},
				kvNamespace,
				expirationTtl,
			);

			payload = (await Jwt.verify(token, publicKey, header?.alg)) as T;
		} catch (e) {
			cause = e;
		}
		if (!payload) {
			throw new HTTPException(401, {
				message: "Unauthorized",
				res: unauthorizedResponse({
					ctx,
					error: "invalid_token",
					statusText: "Unauthorized",
					errDescription: "token verification failure",
				}),
				cause,
			});
		}

		ctx.set("jwtPayload", payload);
		if (subjectToSubContextVariable && subjectToSubContextVariable in payload) {
			ctx.set("sub", payload[subjectToSubContextVariable]);
		}
		await next();
	});
}

async function getPublicKey(
	getJwks: GetJwks,
	options: GetPublicKeyOptions,
	kvNamespace: KVNamespace | undefined,
	expirationTtl: number,
) {
	if (getRuntimeKey() === "workerd") {
		if (kvNamespace === undefined) {
			return await getJwks.getPublicKey(options);
		}
		// Check if the key is in the cache

		// Build the cache key with the domain, alg and kid (skip empty values)
		const cacheKey = Object.entries(options)
			.filter(([, value]) => value)
			.map(([key, value]) => `${key}:${value}`)
			.join("-");

		// Check if the key is in the cache
		const cachedJWKS = await kvNamespace.get(cacheKey, {
			type: "text",
		});

		if (cachedJWKS) {
			return cachedJWKS;
		}
		const publicKey = await getJwks.getPublicKey(options);
		await kvNamespace.put(cacheKey, publicKey, { expirationTtl });
		return publicKey;
	}
	return await getJwks.getPublicKey(options);
}

/**
 * Try to get the token from the Authorization header or cookie
 * @param options Middleware options
 * @param ctx hono context
 * @returns The token or undefined / false if not found
 */
async function getAuthorizationToken(
	options: MiddlewareOptions,
	ctx: Context,
): Promise<string> {
	const credentials = ctx.req.raw.headers.get("Authorization");
	let token: string | undefined | false = false;
	if (credentials) {
		const parts = credentials.split(/\s+/);
		if (parts.length !== 2) {
			const errDescription = "invalid credentials structure";
			throw new HTTPException(401, {
				message: errDescription,
				res: unauthorizedResponse({
					ctx,
					error: "invalid_request",
					errDescription,
				}),
			});
		}
		token = parts[1];
	} else if (options.cookie) {
		if (typeof options.cookie === "string") {
			token = getCookie(ctx, options.cookie);
		} else if (options.cookie.secret) {
			if (options.cookie.prefixOptions) {
				token = await getSignedCookie(
					ctx,
					options.cookie.secret,
					options.cookie.key,
					options.cookie.prefixOptions,
				);
			} else {
				token = await getSignedCookie(
					ctx,
					options.cookie.secret,
					options.cookie.key,
				);
			}
		} else {
			if (options.cookie.prefixOptions) {
				token = getCookie(
					ctx,
					options.cookie.key,
					options.cookie.prefixOptions,
				);
			} else {
				token = getCookie(ctx, options.cookie.key);
			}
		}
	}
	if (!token) {
		throw new HTTPException(401, {
			message: "missing credentials",
			res: unauthorizedResponse({
				ctx,
				error: "invalid_request",
				errDescription: "no authorization included in request",
			}),
		});
	}
	return token;
}

/**
 * Create a response for unauthorized requests
 * Use the WWW-Authenticate header to provide information about the error
 *
 * @param opts Options
 * @returns Response
 */
function unauthorizedResponse(opts: {
	ctx: Context;
	error: string;
	errDescription: string;
	statusText?: string;
}) {
	return new Response("Unauthorized", {
		status: 401,
		statusText: opts.statusText,
		headers: {
			"WWW-Authenticate": `Bearer realm="${opts.ctx.req.url}",error="${opts.error}",error_description="${opts.errDescription}"`,
		},
	});
}
