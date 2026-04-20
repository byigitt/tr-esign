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

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();
const live = process.env.TR_XADES_LIVE_TSA === "1";

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

		// Structural check: signerInfo.unsignedAttrs SignatureTimeStamp içermeli
		const ab = new ArrayBuffer(t.byteLength);
		new Uint8Array(ab).set(t);
		const ci = new pkijs.ContentInfo({ schema: asn1js.fromBER(ab).result });
		assert.equal(ci.contentType, CONTENT_TYPE.signedData);
		const sd = new pkijs.SignedData({ schema: ci.content });
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

test("cadesUpgrade — malformed input throws", async () => {
	await assert.rejects(() => cadesUpgrade({ bytes: new Uint8Array([0, 1, 2, 3]), to: "T" }));
});
