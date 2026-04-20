// CAdES seviye yükseltici. v0.3.0 kapsamında yalnız CAdES-T.
// LT / LTA sonraki sürümlere.
//
// ETSI TS 101 733 §6.1.1 signature-time-stamp: attribute value TimeStampToken;
// messageImprint input = SignerInfo.signature OCTET STRING content octets.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { buildSignatureTimeStampAttr } from "./cades-attributes.ts";
import { CONTENT_TYPE } from "./cades-constants.ts";
import { digest, type HashAlg } from "./crypto.ts";
import { getTimestamp } from "./tsp.ts";

export type CadesUpgradeOptions = {
	bytes: Uint8Array;
	to: "T";
	tsa?: { url?: string; policyOid?: string };
	digestAlgorithm?: HashAlg;
};

export async function cadesUpgrade(opts: CadesUpgradeOptions): Promise<Uint8Array> {
	const asn = asn1js.fromBER(toAB(opts.bytes));
	if (asn.offset === -1) throw new Error("cadesUpgrade: ASN.1 parse hatası");
	const ci = new pkijs.ContentInfo({ schema: asn.result });
	if (ci.contentType !== CONTENT_TYPE.signedData) {
		throw new Error(`cadesUpgrade: ContentType SignedData değil: ${ci.contentType}`);
	}
	const sd = new pkijs.SignedData({ schema: ci.content });
	if (sd.signerInfos.length !== 1) {
		throw new Error(`cadesUpgrade: tek signerInfo bekleniyor, ${sd.signerInfos.length} var`);
	}
	const si = sd.signerInfos[0]!;

	if (opts.to === "T") {
		await addSignatureTimeStamp(si, opts);
	}

	// Re-serialize SignedData → ContentInfo
	const out = new pkijs.ContentInfo({
		contentType: CONTENT_TYPE.signedData,
		content: sd.toSchema(true),
	});
	return new Uint8Array(out.toSchema().toBER());
}

async function addSignatureTimeStamp(
	si: pkijs.SignerInfo,
	opts: Extract<CadesUpgradeOptions, { to: "T" }>,
): Promise<void> {
	const hashAlg = opts.digestAlgorithm ?? "SHA-256";
	const sigBytes = new Uint8Array(si.signature.valueBlock.valueHexView);
	const d = await digest(hashAlg, sigBytes);
	const ts = await getTimestamp({
		digest: d,
		digestAlgorithm: hashAlg,
		tsaUrl: opts.tsa?.url,
		policyOid: opts.tsa?.policyOid,
	});

	const attr = buildSignatureTimeStampAttr(ts.token);
	if (!si.unsignedAttrs) {
		si.unsignedAttrs = new pkijs.SignedAndUnsignedAttributes({ type: 1, attributes: [attr] });
	} else {
		si.unsignedAttrs.attributes = [...si.unsignedAttrs.attributes, attr];
	}
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
