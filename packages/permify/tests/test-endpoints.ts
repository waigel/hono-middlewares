import { createMiddleware } from "hono/factory";
import { createCheckPermissionMiddleware } from "../src/middleware";

import { Hono } from "hono";
const app = new Hono();

const { checkPermission } = createCheckPermissionMiddleware({
	defaultTenantId: "default",
	tenantIdContextVariable: "__request_specified_tenant_id",
	client: {
		cert: null,
		endpoint: "localhost:8000",
	},
});

app.use(
	"*",
	createMiddleware(async (c, next) => {
		c.set("sub", "acct_01j6wwsyzteqqbe76dt28vdfdr");
		await next();
	}),
);

app.get(
	"/test1/team/:teamId",
	checkPermission({
		entity: { id: "teamId", type: "team" },
		permission: "view",
	}),
	(c) => {
		const type1 = c.req.param("teamId");
		expectTypeOf(type1).toEqualTypeOf<string>();
		const { teamId } = c.req.param();
		expectTypeOf(teamId).toEqualTypeOf<string>();
		return c.json({
			teamId,
		});
	},
);

app.post(
	"/test1/team/:teamId/withoutPermission",
	checkPermission({
		entity: { id: "teamId", type: "team" },
	}),
	(c) => {
		const type1 = c.req.param("teamId");
		expectTypeOf(type1).toEqualTypeOf<string>();
		const { teamId } = c.req.param();
		expectTypeOf(teamId).toEqualTypeOf<string>();
		return c.json({
			teamId,
		});
	},
);

app.get(
	"/test1/team/:teamId/unknownMethod",
	checkPermission({
		entity: { id: "teamId", type: "team" },
	}),
	(c) => {
		const type1 = c.req.param("teamId");
		expectTypeOf(type1).toEqualTypeOf<string>();
		const { teamId } = c.req.param();
		expectTypeOf(teamId).toEqualTypeOf<string>();
		return c.json({
			teamId,
		});
	},
);

app.get(
	"/test1/team/:teamId/idNotDefined",
	checkPermission({
		entity: { id: "orgaId", type: "orga" },
	}),
	(c) => {
		const type1 = c.req.param("teamId");
		expectTypeOf(type1).toEqualTypeOf<string>();
		const { teamId } = c.req.param();
		expectTypeOf(teamId).toEqualTypeOf<string>();
		return c.json({
			teamId,
		});
	},
);

app.get(
	"/test1/team/:teamId/context",
	checkPermission({
		entity: { id: "teamId", type: "team" },
	}),
	(ctx) => {
		return ctx.json({
			//@ts-expect-error
			...(ctx.get("_permifyPermissionCheckResponse") ?? {}),
		});
	},
);

app.use(
	"/test1/team/:teamId/contextWithCustomTenant",
	createMiddleware(async (c, next) => {
		c.set("__request_specified_tenant_id", "tenant_01j6ma5p51epc8h28b2my83x8p");
		await next();
	}),
);
app.get(
	"/test1/team/:teamId/contextWithCustomTenant",
	checkPermission({
		entity: { id: "teamId", type: "team" },
	}),
	(ctx) => {
		return ctx.json({
			//@ts-expect-error
			...(ctx.get("_permifyPermissionCheckResponse") ?? {}),
		});
	},
);

/**
 * Testset 2
 * Invalid http method / permission mapping
 */

const { checkPermission: checkPermission2 } = createCheckPermissionMiddleware({
	client: {
		cert: null,
		endpoint: "localhost:8000",
	},
	methodePermissionMapping: {
		//@ts-expect-error  // invalid http method
		GET: null,
	},
});

app.get(
	"/test2/team/:teamId",
	checkPermission2({ entity: { id: "teamId", type: "team" } }),
	() => {
		throw new Error("unreachable");
	},
);

/**
 * Testset 3
 * Not throwing on permission denied
 */

const { checkPermission: checkPermission3 } = createCheckPermissionMiddleware({
	client: {
		cert: null,
		endpoint: "localhost:8000",
	},
	throwOnPermissionDenied: false,
});

app.use(
	"/test3",
	createMiddleware(async (c, next) => {
		c.set("sub", "acct_01j6wwsyzteqqbe76dt28vdfdr");
		await next();
	}),
);

app.get(
	"/test3/team/:teamId",
	checkPermission3({ entity: { id: "teamId", type: "team" } }),
	(ctx) => {
		return ctx.json({
			//@ts-expect-error
			...(ctx.get("_permifyPermissionCheckResponse") ?? {}),
		});
	},
);

/**
 * Testset 4
 * custom checkPermission metadata
 */

const { checkPermission: checkPermission4 } = createCheckPermissionMiddleware({
	client: {
		cert: null,
		endpoint: "localhost:8000",
	},
	permifyPermissionCheckRequestMetadata: {
		depth: 8,
		schemaVersion: "v1",
		snapToken: "snap_01j6wwsyzteqqbe76dt28vdfdr",
	},
});

app.get(
	"/test4/team/:teamId",
	checkPermission4({ entity: { id: "teamId", type: "team" } }),
	(ctx) => {
		return ctx.json({
			//@ts-expect-error
			...(ctx.get("_permifyPermissionCheckResponse") ?? {}),
		});
	},
);

/**
 * Testset 5
 * invalid subject id variable name
 */

const { checkPermission: checkPermission5 } = createCheckPermissionMiddleware({
	client: {
		cert: null,
		endpoint: "localhost:8000",
	},
	permifySubject: {
		idVariableName: "_sub_",
	},
});

app.get(
	"/test5/team/:teamId",
	checkPermission5({ entity: { id: "teamId", type: "team" } }),
	(ctx) => {
		return ctx.json({
			//@ts-expect-error
			...(ctx.get("_permifyPermissionCheckResponse") ?? {}),
		});
	},
);

/**
 * Testset 6
 * custom subject type
 */

const { checkPermission: checkPermission6 } = createCheckPermissionMiddleware({
	client: {
		cert: null,
		endpoint: "localhost:8000",
	},
	permifySubject: {
		type: "user_subject_type",
	},
});

app.get(
	"/test6/team/:teamId",
	checkPermission6({ entity: { id: "teamId", type: "team" } }),
	(ctx) => {
		return ctx.json({
			//@ts-expect-error
			...(ctx.get("_permifyPermissionCheckResponse") ?? {}),
		});
	},
);

export default app;
