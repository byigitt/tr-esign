import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { cadesSign } from "../src/cades-sign.ts";
import { cadesUpgrade } from "../src/cades-upgrade.ts";
import { cadesVerify } from "../src/cades-verify.ts";
import { CADES_ATTR, CONTENT_TYPE } from "../src/cades-constants.ts";
import { loadPfx } from "../src/pfx.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();
const live = process.env.TR_XADES_LIVE_TSA === "1";

function parseSd(bytes: Uint8Array): pkijs.SignedData {
	const ab = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(ab).set(bytes);
	const ci = new pkijs.ContentInfo({ schema: asn1js.fromBER(ab).result });
	assert.equal(ci.contentType, CONTENT_TYPE.signedData);
	return new pkijs.SignedData({ schema: ci.content });
}

test("cadesUpgrade — BES → T with FreeTSA",
	{ skip: (!hasPfx || !live) && "needs fixture + TR_XADES_LIVE_TSA=1" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const data = new TextEncoder().encode("CAdES-T test");
		const bes = await cadesSign({ data, signer: { pfx, password: "testpass" } });
		const t = await cadesUpgrade({
			bytes: bes,
			to: "T",
			tsa: { url: "https://freetsa.org/tsr" },
		});

		const sd = parseSd(t);
		const unsigned = sd.signerInfos[0]!.unsignedAttrs?.attributes ?? [];
		assert.ok(
			unsigned.some((a) => a.type === CADES_ATTR.signatureTimeStamp),
			"signatureTimeStamp unsigned attribute bekleniyor",
		);

		// Verify level=T raporlar
		const r = await cadesVerify(t);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "T");
	});

test("cadesUpgrade — BES → LT with chain (offline)",
	{ skip: !hasPfx && "fixture yok" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const loaded = await loadPfx(pfx, "testpass");
		const data = new TextEncoder().encode("CAdES-LT test");
		const bes = await cadesSign({ data, signer: { pfx, password: "testpass" } });
		// Self-signed test cert: chain = [leaf] (kendi kendisi root).
		const lt = await cadesUpgrade({ bytes: bes, to: "LT", chain: [loaded.certificate] });

		const sd = parseSd(lt);
		const unsigned = sd.signerInfos[0]!.unsignedAttrs?.attributes ?? [];
		assert.ok(
			unsigned.some((a) => a.type === CADES_ATTR.certValues),
			"certValues unsigned attribute bekleniyor",
		);
		// crls/ocsps verilmediyse revocationValues olmamalı
		assert.equal(
			unsigned.some((a) => a.type === CADES_ATTR.revocationValues),
			false,
			"revocation verilmedi ama revocationValues yazıldı",
		);
		// verify level → LT (spec: certValues + revocationValues ikisi de LT; certValues
		// tek başına level tespiti için yeterli sayılır)
		const r = await cadesVerify(lt);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "LT");
	});

test("cadesUpgrade — BES → T → LT → LTA round-trip (live TSA)",
	{ skip: (!hasPfx || !live) && "needs fixture + TR_XADES_LIVE_TSA=1" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const loaded = await loadPfx(pfx, "testpass");
		const data = new TextEncoder().encode("CAdES-LTA test");
		const bes = await cadesSign({ data, signer: { pfx, password: "testpass" } });

		const t = await cadesUpgrade({ bytes: bes, to: "T", tsa: { url: "https://freetsa.org/tsr" } });
		const lt = await cadesUpgrade({ bytes: t, to: "LT", chain: [loaded.certificate] });
		const lta = await cadesUpgrade({ bytes: lt, to: "LTA", tsa: { url: "https://freetsa.org/tsr" } });

		const sd = parseSd(lta);
		const unsigned = sd.signerInfos[0]!.unsignedAttrs?.attributes ?? [];
		const types = new Set(unsigned.map((a) => a.type));
		assert.ok(types.has(CADES_ATTR.signatureTimeStamp), "T attribute bekleniyor");
		assert.ok(types.has(CADES_ATTR.certValues), "LT attribute bekleniyor");
		assert.ok(types.has(CADES_ATTR.archiveTimeStampV2), "LTA attribute bekleniyor");

		const r = await cadesVerify(lta);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "LTA");
	});

test("cadesUpgrade — malformed input throws", async () => {
	await assert.rejects(() => cadesUpgrade({ bytes: new Uint8Array([0, 1, 2, 3]), to: "T" }));
});
