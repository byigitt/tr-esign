// Multi-signature (paralel) testleri.
//
// `ubl-ma3-compat` modu multi-sig'i doğal olarak destekler: her sign() çağrısı
// ExtensionContent'e yeni bir ds:Signature ekler; her sig'in kendi ds:Object'inde
// input XML base64 halinde — sigler bağımsız, birbirine bağımlı değil.
// Bu yüzden ayrı "add-signature" placement modu yok (tek-yol kuralı).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { DOMParser } from "@xmldom/xmldom";
import { sign } from "../src/sign.ts";
import { verify } from "../src/verify.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const SAMPLE = join(import.meta.dirname, "..", "reference", "fixtures", "sample-invoice.xml");
const hasPfx = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("multi-sig — ubl-ma3-compat'ın tekrar çağrılması paralel sig ekler",
	{ skip: !hasPfx && "run reference/run.sh" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const base = readFileSync(SAMPLE, "utf8");

		const first = await sign({
			input: { xml: base, placement: "ubl-ma3-compat" },
			signer: { pfx, password: "testpass" },
			signingTime: new Date("2026-01-01T10:00:00Z"),
		});
		const second = await sign({
			input: { xml: first, placement: "ubl-ma3-compat" },
			signer: { pfx, password: "testpass" },
			signingTime: new Date("2026-01-02T10:00:00Z"),
		});

		// İki bağımsız ds:Signature
		const doc = new DOMParser().parseFromString(second, "text/xml");
		const sigs = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
		assert.equal(sigs.length, 2, "iki ds:Signature bekleniyor");

		// Her iki sig de kendi ds:Object (base64) referansına sahip — karşılıklı bağımlılık yok
		const objCount = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Object").length;
		// Her sig için: 1 QP Object + 1 data Object = 2 Object. Toplam 4 bekleniyor (en az).
		assert.ok(objCount >= 4, `Object sayısı beklenenden az: ${objCount}`);

		// verify() ilk sig'i doğrular (4.2'de allSignatures ile genişletilecek)
		const r = await verify(second);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
	});
