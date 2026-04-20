import { test } from "node:test";
import assert from "node:assert/strict";
import { parseOcspResponse } from "../src/ocsp.ts";

test("parseOcspResponse — rejects malformed bytes", () => {
	assert.throws(() => parseOcspResponse(new Uint8Array([0, 1, 2, 3]), "x"));
});

// Live OCSP test requires a real chain (self-signed test.p12 has no issuer to ask).
// Deferred: enable when we have a real TR mali mühür test PFX + issuer cert.
test("checkOcsp — live (manual, needs real chain)", { skip: true }, () => {});
