import { PermissionCheckRequestSchema } from "@buf/permifyco_permify.bufbuild_es/base/v1/service_pb";
import { create } from "@bufbuild/protobuf";

const defaultMockMetadata = {
	metadata: {
		$typeName: "base.v1.PermissionCheckRequestMetadata",
		depth: 3,
		schemaVersion: "",
		snapToken: "",
	},
};

const checkPermissionMock = vi.fn(async () => {
	return Promise.resolve({
		can: true,
	});
});

vi.mock("@permify/permify-node", async () => {
	const permifyImport = await import("@permify/permify-node");
	return {
		grpc: {
			...permifyImport.grpc,
			newClient: () => {
				return {
					permission: {
						check: checkPermissionMock,
					},
				};
			},
		},
	};
});

describe("middleware", async () => {
	const app = await (await import("../tests/test-endpoints")).default;
	it("should have permission 'view' on 'team' for subject", async () => {
		const res = await app.request("http://localhost/test1/team/team_1");
		expect(res.status).toBe(200);
		expect(checkPermissionMock).toHaveBeenCalledWith(
			create(PermissionCheckRequestSchema, {
				metadata: defaultMockMetadata.metadata,
				entity: {
					type: "team",
					id: "team_1",
				},
				permission: "view",
				subject: {
					type: "user",
					id: "acct_01j6wwsyzteqqbe76dt28vdfdr",
				},
				tenantId: "default",
			}),
		);
		expect(await res.json()).toEqual({
			teamId: "team_1",
		});
	});

	it("should missing permission 'view' on 'team' for subject", async () => {
		checkPermissionMock.mockImplementationOnce(async () => {
			return Promise.resolve({
				can: false,
			});
		});

		const res = await app.request("http://localhost/test1/team/team_1");
		expect(res.status).toBe(403);
		expect(checkPermissionMock).toHaveBeenCalledWith(
			create(PermissionCheckRequestSchema, {
				metadata: defaultMockMetadata.metadata,
				entity: {
					type: "team",
					id: "team_1",
				},
				permission: "view",
				subject: {
					type: "user",
					id: "acct_01j6wwsyzteqqbe76dt28vdfdr",
				},
				tenantId: "default",
			}),
		);
	});

	it("should check permission based on req method", async () => {
		const res = await app.request(
			"http://localhost/test1/team/team_1/withoutPermission",
			{
				method: "POST",
			},
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({
			teamId: "team_1",
		});
	});

	it("should throw 500 if no permission for method found", async () => {
		const res = await app.request("http://localhost/test2/team/team_1");
		expect(res.status).toBe(500);
		expect(await res.text()).toEqual(
			"PERMIFY: No permission mapping found for method 'GET'",
		);
	});

	it("should throw 400 if entity id not found in request params", async () => {
		const res = await app.request(
			"http://localhost/test1/team/team_1/idNotDefined",
		);
		expect(res.status).toBe(400);
		expect(await res.text()).toEqual(
			"PERMIFY: Entity ID 'orgaId' not found in the request parameters",
		);
	});

	it("should throw 403 if permission denied", async () => {
		checkPermissionMock.mockImplementationOnce(async () => {
			return Promise.resolve({
				can: false,
			});
		});

		const res = await app.request("http://localhost/test1/team/team_1");
		expect(res.status).toBe(403);
		expect(await res.text()).toEqual(
			"PERMIFY: Permission denied for team team_1",
		);
	});

	it("should throw 500 if permission check fails", async () => {
		checkPermissionMock.mockImplementationOnce(async () => {
			throw new Error("boom");
		});

		const res = await app.request("http://localhost/test1/team/team_1");
		expect(res.status).toBe(500);
		expect(await res.text()).toEqual("Internal Server Error");
	});

	it("should validate internal permission check response is set to context", async () => {
		const res = await app.request("http://localhost/test1/team/team_1/context");
		expect(await res.json()).toEqual({
			request: {
				entity: {
					id: "team_1",
					type: "team",
				},
				metadata: {
					depth: 3,
				},
				permission: "view",
				subject: {
					id: "acct_01j6wwsyzteqqbe76dt28vdfdr",
					type: "user",
				},
				tenantId: "default",
			},
			result: {
				can: true,
			},
		});
	});

	it("should use the request specific tenantId", async () => {
		const res = await app.request(
			"http://localhost/test1/team/team_1/contextWithCustomTenant",
		);
		expect(await res.json()).toEqual({
			request: {
				entity: {
					id: "team_1",
					type: "team",
				},
				metadata: {
					depth: 3,
				},
				permission: "view",
				subject: {
					id: "acct_01j6wwsyzteqqbe76dt28vdfdr",
					type: "user",
				},
				tenantId: "tenant_01j6ma5p51epc8h28b2my83x8p",
			},
			result: {
				can: true,
			},
		});
	});

	it("should not throw on permission denied when 'throwOnPermissionDenied' is false", async () => {
		checkPermissionMock.mockImplementationOnce(async () => {
			return Promise.resolve({
				can: false,
			});
		});

		const res = await app.request("http://localhost/test3/team/team_1");
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({
			request: {
				entity: {
					id: "team_1",
					type: "team",
				},
				metadata: {
					depth: 3,
				},
				permission: "view",
				subject: {
					type: "user",
					id: "acct_01j6wwsyzteqqbe76dt28vdfdr",
				},
			},
			result: {
				can: false,
			},
		});
	});

	it("should use custom defined permission check request params", async () => {
		const res = await app.request("http://localhost/test4/team/team_1");
		expect(await res.json()).toEqual({
			request: {
				entity: {
					id: "team_1",
					type: "team",
				},
				metadata: {
					depth: 8,
					schemaVersion: "v1",
					snapToken: "snap_01j6wwsyzteqqbe76dt28vdfdr",
				},
				permission: "view",
				subject: {
					id: "acct_01j6wwsyzteqqbe76dt28vdfdr",
					type: "user",
				},
			},
			result: {
				can: true,
			},
		});
	});

	it("should throw 400 if subject id is not found", async () => {
		const res = await app.request("http://localhost/test5/team/team_1");
		expect(res.status).toBe(400);
		expect(await res.text()).toEqual(
			"PERMIFY: Subject ID '_sub_' not found in request context",
		);
	});

	it("should use custom subject type", async () => {
		const res = await app.request("http://localhost/test6/team/team_1");
		expect(await res.json()).toEqual({
			request: {
				entity: {
					id: "team_1",
					type: "team",
				},
				metadata: {
					depth: 3,
				},
				permission: "view",
				subject: {
					id: "acct_01j6wwsyzteqqbe76dt28vdfdr",
					type: "user_subject_type",
				},
			},
			result: {
				can: true,
			},
		});
	});
});
