import type { HTTPMethod } from "./middleware";

export const defaultMethodePermissionMapping: Record<HTTPMethod, string> = {
	GET: "view",
	OPTIONS: "view",
	POST: "create",
	PUT: "update",
	PATCH: "update",
	DELETE: "delete",
};
