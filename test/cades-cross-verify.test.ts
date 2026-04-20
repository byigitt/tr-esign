// MA3 CAdES fixture'ı ile cadesVerify interop testi.
// reference/out/cades-bes.p7s yoksa skip edilir.
// (Self-signed test cert'imiz MA3'ün path validation'ına uymadığından fixture
// üretilemedi; ileride gerçek mali mühür zinciri ile çalışacak.)

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { cadesVerify } from "../src/cades-verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "out", "cades-bes.p7s");
const has = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("cades-cross-verify — MA3 CAdES-BES fixture'ı cadesVerify ile doğrulanır",
	{ skip: !has && "MA3 fixture yok (reference/out/cades-bes.p7s) — gerçek mali mühür chain gerekir" },
	async () => {
		const bytes = new Uint8Array(readFileSync(FIXTURE));
		const r = await cadesVerify(bytes);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		// MA3'ün ürettiği her BES sig signingCertV2 taşır (RFC 5035) → level "BES"
		assert.ok(r.level === "BES" || r.level === "EPES");
	});
