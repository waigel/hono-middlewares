import { PermissionCheckRequestSchema } from "@buf/permifyco_permify.bufbuild_es/base/v1/service_pb";
import { create } from "@bufbuild/protobuf";
import * as permify from "@permify/permify-node";
import type { MiddlewareHandler } from "hono";
import { createMiddleware } from "hono/factory";
import { HTTPException } from "hono/http-exception";
import { defaultMethodePermissionMapping } from "./defaults";
import { tinyassert } from "./util/tinyassert";

export type HTTPMethod =
	| "GET"
	| "OPTIONS"
	| "POST"
	| "PUT"
	| "PATCH"
	| "DELETE";

interface MiddlewareOptions {
	client: permify.grpc.Config;

	/**
	 * Override the default permission mapping for the REST API.
	 * @default The default mapping is:
	 *  GET    -> view
	 *  POST   -> create
	 *  PUT    -> update
	 *  PATCH  -> update
	 *  DELETE -> delete
	 */
	methodePermissionMapping?: Record<HTTPMethod, string>;
	/**
	 * The default tenant ID to use for permission checks.
	 * https://docs.permify.co/use-cases/multi-tenancy#tenancy-based-apis
	 *
	 * You can use a custom tenant ID for each request by setting the tenant ID in the request metadata.
	 * You can define a context variable name with 'tenantIdContextVariable' property.
	 */
	defaultTenantId?: string;

	/**
	 * The name of the context variable that contains the tenant ID.
	 * If this property is set, the middleware will use the tenant ID from the context variable instead of the default tenant ID.
	 *
	 * If the context variable is not set, the default tenant ID will be used.
	 * @default undefined - The middleware will use the default tenant ID.
	 */
	tenantIdContextVariable?: string;

	/**
	 * The metadata for the permission check request.
	 * https://buf.build/permifyco/permify/docs/main:base.v1#base.v1.PermissionCheckRequestMetadata
	 */
	permifyPermissionCheckRequestMetadata?: {
		schemaVersion?: string;
		snapToken?: string;
		depth?: number;
	};

	/**
	 * Define the subject type name for the permission check request.
	 * @default { type: "user", idVariableName: "sub" }
	 */
	permifySubject?: {
		type?: string;
		idVariableName?: string;
	};

	/**
	 * Throw an exception if the permission is denied.
	 * Otherwise you can handle the permission dienied case by yourself with the c.get("permifyPermissionCheckResponse") method.
	 * @default true - The middleware will not throw an exception if the permission is denied.
	 */
	throwOnPermissionDenied?: boolean;
}

type CheckPermissionFunction = (args: {
	entity: {
		type: string;
		id: string;
	};
	permission?: string;
}) => MiddlewareHandler;

export function createCheckPermissionMiddleware(options: MiddlewareOptions): {
	checkPermission: CheckPermissionFunction;
} {
	const {
		methodePermissionMapping = defaultMethodePermissionMapping,
		defaultTenantId,
		tenantIdContextVariable,
		permifySubject,
		throwOnPermissionDenied = true,
	} = options;

	return {
		checkPermission: ({
			entity,
			permission,
		}: Parameters<CheckPermissionFunction>[0]) => {
			return createMiddleware(async (ctx, next) => {
				tinyassert(entity, "entity is required");
				tinyassert(entity.id, "entity.id is required");
				tinyassert(entity.type, "entity.type is required");

				const client = permify.grpc.newClient(options.client);

				// Get the tenant ID from the context variable or use the default tenant ID
				const requestTenantId =
					tenantIdContextVariable && ctx.get(tenantIdContextVariable)
						? ctx.get(tenantIdContextVariable)
						: defaultTenantId;

				// Find the permission for the HTTP method
				const requestPermission =
					permission ?? methodePermissionMapping[ctx.req.method as HTTPMethod];
				if (!requestPermission) {
					throw new HTTPException(500, {
						message: `PERMIFY: No permission mapping found for method '${ctx.req.method}'`,
					});
				}

				const params: Record<string, string> = ctx.req.param();
				const entityId = entity.id;
				const entityIdValue = entityId in params ? params[entityId] : null;
				if (!entityIdValue) {
					throw new HTTPException(400, {
						message: `PERMIFY: Entity ID '${entity.id}' not found in the request parameters`,
					});
				}

				const {
					depth = 3,
					schemaVersion,
					snapToken,
				} = options.permifyPermissionCheckRequestMetadata || {};

				const subjectId = ctx.get(permifySubject?.idVariableName || "sub");
				if (!subjectId) {
					throw new HTTPException(400, {
						message: `PERMIFY: Subject ID '${permifySubject?.idVariableName}' not found in request context`,
					});
				}

				const permissionCheckRequest = {
					tenantId: requestTenantId,
					entity: {
						type: entity.type,
						id: entityIdValue,
					},
					permission: requestPermission,
					subject: {
						type: permifySubject?.type || "user",
						id: ctx.get(permifySubject?.idVariableName || "sub"),
					},
					metadata: {
						snapToken,
						depth,
						schemaVersion,
					},
				};

				const result: permify.grpc.payload.PermissionCheckResponse =
					await client.permission.check(
						create(PermissionCheckRequestSchema, permissionCheckRequest),
					);

				// Set the raw result to context for further processing (e.g. logging, vertification of check)
				ctx.set("_permifyPermissionCheckResponse", {
					result: result,
					request: permissionCheckRequest,
				});
				if (result.can !== true) {
					if (throwOnPermissionDenied) {
						throw new HTTPException(403, {
							message: `PERMIFY: Permission denied for ${entity.type} ${entityIdValue}`,
						});
					}
				}
				await next();
			});
		},
	};
}
