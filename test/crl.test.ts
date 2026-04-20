import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCrl, isRevoked } from "../src/crl.ts";

test("parseCrl — rejects malformed bytes", () => {
	assert.throws(() => parseCrl(new Uint8Array([0, 1, 2, 3])));
});

test("isRevoked — lookup by serialHex (lowercase-insensitive)", () => {
	// Synthetic Crl object — avoid fetching a real CRL in unit tests.
	const crl = {
		der: new Uint8Array(),
		thisUpdate: new Date(),
		issuerLdap: "CN=Test",
		revoked: new Map([["deadbeef", { date: new Date("2025-01-01"), reason: 1 }]]),
	};
	assert.deepEqual(isRevoked(crl, "DEADBEEF"), { date: new Date("2025-01-01"), reason: 1 });
	assert.equal(isRevoked(crl, "00112233"), null);
});
