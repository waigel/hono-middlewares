import { describe, expect, it } from "vitest";
import { extractEntityAndId } from "./entity-mapper";

describe("extractEntityAndId", () => {
	it("should extract a single entity and ID from a params object", () => {
		const params = { userId: "1" };
		const result = extractEntityAndId(params);
		expect(result).toEqual([{ type: "user", id: "1" }]);
	});

	it("should extract multiple entities and IDs from a params object", () => {
		const params = {
			teamId: "456",
			deploymentId: "789",
		};
		const result = extractEntityAndId(params);
		expect(result).toEqual([
			{ type: "team", id: "456" },
			{ type: "deployment", id: "789" },
		]);
	});

	it("should handle routes with multiple entities and IDs in a params object", () => {
		const params = {
			companyId: "1001",
			projectId: "2022",
			taskId: "3003",
		};
		const result = extractEntityAndId(params);
		expect(result).toEqual([
			{ type: "company", id: "1001" },
			{ type: "project", id: "2022" },
			{ type: "task", id: "3003" },
		]);
	});

	it("should return an empty array for an empty params object", () => {
		const params = {};
		const result = extractEntityAndId(params);
		expect(result).toEqual([]);
	});

	it("should correctly parse params with hyphens or underscores in IDs", () => {
		const params = { userId: "user_123-abc" };
		const result = extractEntityAndId(params);
		expect(result).toEqual([{ type: "user", id: "user_123-abc" }]);
	});

	it("should correctly parse params with duplicated 'Id' suffixes", () => {
		const params = { userIdId: "1" };
		const result = extractEntityAndId(params);
		expect(result).toEqual([{ type: "userId", id: "1" }]);
	});

	it("should only match 'Id' suffixes at the end of the key", () => {
		const params = { userIdParam: "1", idParam: "2", user: "3" };
		const result = extractEntityAndId(params);
		expect(result).toEqual([]);
	});
});
