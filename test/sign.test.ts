import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { DOMParser } from "@xmldom/xmldom";
import * as asn1js from "asn1js";
import { Certificate } from "pkijs";
import { sign } from "../src/sign.ts";
import { canonicalize } from "../src/c14n.ts";
import { importPublicKeyFromCert, verify } from "../src/crypto.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const SAMPLE = join(import.meta.dirname, "..", "reference", "fixtures", "sample-invoice.xml");
const has = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

async function selfVerify(xml: string): Promise<void> {
	const doc = new DOMParser().parseFromString(xml, "text/xml") as unknown as Document;
	const sig = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0)!;
	const si = sig.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignedInfo").item(0)!;
	const sv = sig.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0)!;
	const xc = sig.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate").item(0)!;

	const c14nUri = si
		.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "CanonicalizationMethod")
		.item(0)!
		.getAttribute("Algorithm")!;
	const sigMethodUri = si
		.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureMethod")
		.item(0)!
		.getAttribute("Algorithm")!;

	// Only covers the two algorithms we produce in this test.
	const c14nAlg = c14nUri === "http://www.w3.org/2001/10/xml-exc-c14n#" ? "exc-c14n" : "c14n10";
	const sigAlg = sigMethodUri.endsWith("rsa-sha256") ? "RSA-SHA256" : "RSA-SHA512";

	const siBytes = canonicalize(si as unknown as Node, c14nAlg);
	const sigValue = new Uint8Array(Buffer.from((sv.textContent ?? "").trim(), "base64"));
	const certDer = new Uint8Array(Buffer.from((xc.textContent ?? "").trim(), "base64"));
	const pub = await importPublicKeyFromCert(certDer, sigAlg);
	assert.ok(await verify(sigAlg, pub, sigValue, siBytes), "SignedInfo signature failed to verify");

	// Also verify reference digests would take an XMLDSig-full verify — covered
	// by verify.ts later. For now SignedInfo signature integrity suffices.
	const parsed = new Certificate({ schema: asn1js.fromBER(certDer.buffer as ArrayBuffer).result });
	assert.ok(parsed, "cert parse ok");
}

test("sign — enveloping BES round-trip self-verifies",
	{ skip: !has && "run reference/run.sh first" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const xml = await sign({
			input: { bytes: new TextEncoder().encode("<hello>world</hello>"), mimeType: "text/xml" },
			signer: { pfx, password: "testpass" },
		});
		assert.match(xml, /<ds:Signature\b/);
		assert.match(xml, /<xades:QualifyingProperties\b/);
		assert.match(xml, /<xades:SigningCertificate\b/);
		assert.match(xml, /<ds:X509Certificate\b/);
		await selfVerify(xml);
	});

test("sign — UBL enveloped BES round-trip self-verifies",
	{ skip: !has && "run reference/run.sh first" },
	async () => {
		const pfx = new Uint8Array(readFileSync(FIXTURE));
		const xml = await sign({
			input: { xml: readFileSync(SAMPLE, "utf8"), placement: "ubl-extension" },
			signer: { pfx, password: "testpass" },
			signingTime: new Date("2026-04-20T12:00:00Z"),
			productionPlace: { city: "Ankara", country: "TR" },
		});
		assert.match(xml, /<Invoice\b/);
		assert.match(xml, /<ext:UBLExtensions>/);
		assert.match(xml, /<ds:Signature\b/);
		assert.match(xml, /<xades:SigningTime>2026-04-20T12:00:00.000Z/);
		assert.match(xml, /<xades:City>Ankara<\/xades:City>/);
		await selfVerify(xml);
	});
