// MA3 PAdES fixture'ı ile padesVerify interop testi.
// reference/out/pades-bes.pdf yoksa skip edilir.
// v0.7'de docker-ocsp + test-chain.p12 ile fixture üretimi açıldı; bu test
// artık loop içinde gerçek PASS ediyor. Skip yalnız fixture generate edilmemiş
// temiz checkout senaryosu için korunuyor.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { padesVerify } from "../src/pades-verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "out", "pades-bes.pdf");
const has = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("pades-cross-verify — MA3 PAdES-BES fixture'ı padesVerify ile doğrulanır",
	{ skip: !has && "MA3 fixture yok (cd reference && ./run.sh)" },
	async () => {
		const bytes = new Uint8Array(readFileSync(FIXTURE));
		const r = await padesVerify(bytes);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
		assert.match(r.signer.subject, /CN=Test Signer/);
		assert.match(r.signer.issuer, /Intermediate CA/);
	});
