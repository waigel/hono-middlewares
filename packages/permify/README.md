# @hono-middlewares/permify
This package provides a middleware for Hono to check permissions against permify endpoints.

## Installation
```bash
npm i @hono-middlewares/permify
```

## Usage

```typescript
const app = new Hono();

// Init the permify middleware with the permify client
const { checkPermission } = createCheckPermissionMiddleware({
	client: {
		cert: null,
		endpoint: "localhost:3476",
	},
});

// Set the subject id for permify validation
// If you using the @hono-middlewares/jwks middleware, you can skip this step
// because the middleware will set the subject id automatically
app.use("*", createMiddleware(async (c, next) => {
    c.set("sub", "acct_01j6wwsyzteqqbe76dt28vdfdr");
    await next();
}));

// Define endpoiunt with checkPermission middleware
app.get("/team/:teamId", checkPermission({
		entity: { id: "teamId", type: "team" },
		permission: "view",
	}),
	(c) => {
		c.text("Authorized to view team");
	},
);
```
---

Licensed under the MIT License.