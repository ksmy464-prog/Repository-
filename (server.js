const apiKey = process.env.GEMINI_API_KEY;

if (!apiKey) {
	console.error("Set the GEMINI_API_KEY environment variable first.");
	process.exitCode = 1;
} else {
	fetch("https://generativelanguage.googleapis.com/v1beta/interactions", {
		method: "POST",
		headers: {
			"x-goog-api-key": apiKey,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({
			model: "gemini-flash-latest",
			input: "Explain how TCP congestion control works in two sentences.",
		}),
	})
		.then(async (response) => {
			const body = await response.text();
			if (!response.ok) {
				throw new Error(`Gemini API returned ${response.status}: ${body}`);
			}
			console.log(body);
		})
		.catch((error) => {
			console.error(error.message);
			process.exitCode = 1;
		});
}
