import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { sign } from "../src/sign.ts";
import { upgrade } from "../src/upgrade.ts";
import { verify } from "../src/verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();
const live = process.env.TR_XADES_LIVE_TSA === "1";

test("upgrade — BES → LT (chain + CertificateValues, no T)",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const { loadPfx } = await import("../src/pfx.ts");
		const b = await loadPfx(pfx, "testpass");
		const bes = await sign({
			input: { bytes: new TextEncoder().encode("<x/>"), mimeType: "text/xml" },
			signer: { pfx, password: "testpass" },
		});
		const lt = await upgrade({ xml: bes, to: "LT", chain: [b.certificate] });
		assert.match(lt, /<xades:CertificateValues\b/);
		assert.match(lt, /<xades:EncapsulatedX509Certificate\b/);
		const r = await verify(lt);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "LT");
	});

test("upgrade — BES → T with FreeTSA",
	{ skip: (!hasPfx || !live) && "needs fixture + TR_XADES_LIVE_TSA=1" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const bes = await sign({
			input: { bytes: new TextEncoder().encode("<x/>"), mimeType: "text/xml" },
			signer: { pfx, password: "testpass" },
		});
		const t = await upgrade({ xml: bes, to: "T", tsa: { url: "https://freetsa.org/tsr" } });
		assert.match(t, /<xades:SignatureTimeStamp\b/);
		assert.match(t, /<xades:UnsignedSignatureProperties\b/);
		assert.match(t, /<xades:EncapsulatedTimeStamp\b/);
		const r = await verify(t);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "T");
	});

test("upgrade — LT → LTA with FreeTSA",
	{ skip: (!hasPfx || !live) && "needs fixture + TR_XADES_LIVE_TSA=1" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const { loadPfx } = await import("../src/pfx.ts");
		const b = await loadPfx(pfx, "testpass");
		const bes = await sign({
			input: { bytes: new TextEncoder().encode("<x/>"), mimeType: "text/xml" },
			signer: { pfx, password: "testpass" },
		});
		const lt = await upgrade({ xml: bes, to: "LT", chain: [b.certificate] });
		const lta = await upgrade({ xml: lt, to: "LTA", tsa: { url: "https://freetsa.org/tsr" } });
		assert.match(lta, /<xades:ArchiveTimeStamp\b/);
		const r = await verify(lta);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "LTA");
	});
