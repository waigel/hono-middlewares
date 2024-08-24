# @hono-middlewares/jwks
This package provides a middleware for Hono to validate JWT tokens using a JWKS endpoint.

## Installation
```bash
pnpm add @hono-middlewares/jwks
```

## Usage

```typescript
const app = new Hono();
app.use("*", jwks({ domain: "https://example.com"}));
```
