import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { cadesSign } from "../src/cades-sign.ts";
import { cadesVerify } from "../src/cades-verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("cadesSign → cadesVerify round-trip (attached, BES)",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const data = new TextEncoder().encode("CAdES round trip");
		const der = await cadesSign({
			data,
			signer: { pfx, password: "testpass" },
			signingTime: new Date("2026-04-20T10:00:00Z"),
		});
		const r = await cadesVerify(der);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
		assert.equal(r.signer.subject, "CN=Test Signer,O=tr-esign test,C=TR");
		assert.equal(r.signedAt?.toISOString(), "2026-04-20T10:00:00.000Z");
	});

test("cadesSign → cadesVerify (detached + detachedContent)",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const data = new TextEncoder().encode("external payload");
		const der = await cadesSign({
			data,
			signer: { pfx, password: "testpass" },
			contentIncluded: false,
		});
		// Doğru content ile verify → VALID
		const ok = await cadesVerify(der, { detachedContent: data });
		assert.equal(ok.valid, true, ok.valid ? "" : `invalid: ${ok.reason}`);

		// Yanlış content → invalid
		const wrong = await cadesVerify(der, { detachedContent: new TextEncoder().encode("tampered") });
		assert.equal(wrong.valid, false);
	});

test("cadesVerify — detached imzada content yoksa reddet",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const der = await cadesSign({
			data: new TextEncoder().encode("x"),
			signer: { pfx, password: "testpass" },
			contentIncluded: false,
		});
		const r = await cadesVerify(der);
		assert.equal(r.valid, false);
		if (r.valid) return;
		assert.match(r.reason, /detachedContent|attached/);
	});

test("cadesVerify — malformed DER reddet", async () => {
	const r = await cadesVerify(new Uint8Array([0, 1, 2, 3, 4]));
	assert.equal(r.valid, false);
});

test("cadesSign (TR P3 policy) → cadesVerify EPES raporlar",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const data = new TextEncoder().encode("e-reçete örneği");
		const der = await cadesSign({
			data,
			signer: { pfx, password: "testpass" },
			policy: "P3", // TR e-fatura profili
			commitmentType: "proof-of-origin",
		});
		const r = await cadesVerify(der);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "EPES", "SignaturePolicyIdentifier eklenince level EPES olmalı");
	});
