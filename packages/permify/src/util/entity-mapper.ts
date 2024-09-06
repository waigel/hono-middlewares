type ExtractedEntity = {
	type: string;
	id: string | undefined;
};

export function extractEntityAndId(
	params: Record<string, string>,
): ExtractedEntity[] {
	return Object.keys(params)
		.filter((paramKey) => /Id$/.test(paramKey)) // Only match keys that end with "Id"
		.map((paramKey) => {
			const entityName = paramKey.replace(/Id$/, ""); // Remove "Id" suffix at the end
			const entityId = params[paramKey];
			return { type: entityName, id: entityId };
		});
}
