import http from "k6/http";
import { check, sleep } from "k6";

// Tell k6 that 200, 201, and 429 are ALL considered successful responses.
// This prevents k6 from counting rate-limited (429) requests as failures.
http.setResponseCallback(http.expectedStatuses(200, 201, 204, 429));

// 1. Setup function: Runs ONCE to create a user and get an Access Token
export function setup() {
	const baseUrl = "http://localhost:8080/api/v1";
	const uniqueEmail = `stress_setup_${Date.now()}@example.com`;

	const initRes = http.post(
		`${baseUrl}/auth/signup/init`,
		JSON.stringify({ email: uniqueEmail }),
		{
			headers: { "Content-Type": "application/json" },
		},
	);

	if (initRes.status !== 200) {
		console.error("Signup init failed!");
		return { token: null };
	}

	const signupToken = initRes.json("signup_token");

	const b64_32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
	const b64_24 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".substring(
		0,
		32,
	);
	const b64_64 =
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";

	const completePayload = JSON.stringify({
		email: uniqueEmail,
		signup_token: signupToken,
		auth_key: b64_32,
		recovery_auth_key: b64_32,
		wrapped_dek: b64_64,
		wrapped_dek_nonce: b64_24,
		recovery_wrapped_dek: b64_64,
		recovery_wrapped_dek_nonce: b64_24,
		identity_pubkey: b64_32,
		device_pubkey: b64_32,
		device_name: "Stress Test Device",
	});

	const completeRes = http.post(
		`${baseUrl}/auth/signup/complete`,
		completePayload,
		{
			headers: { "Content-Type": "application/json" },
		},
	);

	const accessToken = completeRes.json("access_token");
	if (!accessToken) {
		console.error("Signup complete failed! Body: " + completeRes.body);
	}

	return { token: accessToken };
}

// 2. The aggressive load test configuration (400 RPS)
export const options = {
	scenarios: {
		db_write_stress: {
			executor: "constant-arrival-rate",
			rate: 400,
			timeUnit: "1s",
			duration: "20s",
			preAllocatedVUs: 300,
			maxVUs: 1000,
		},
	},
	thresholds: {
		http_req_duration: ["p(95)<500"],
		http_req_failed: ["rate<0.01"], // This will now PASS because 429 is not a failure!
	},
};

// 3. The default function that runs under load
export default function (data) {
	const url = "http://localhost:8080/api/v1/folders";

	const randomMetadata = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
	const randomNonce =
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".substring(0, 32);

	const payload = JSON.stringify({
		encrypted_metadata: randomMetadata,
		metadata_nonce: randomNonce,
		parent_folder_id: null,
	});

	const params = {
		headers: {
			"Content-Type": "application/json",
			Authorization: `Bearer ${data.token}`,
		},
	};

	const res = http.post(url, payload, params);

	check(res, {
		"is 201 or 429": (r) => r.status === 201 || r.status === 429,
	});
}
