// CAdES counter-signature — RFC 5652 §11.4 + RFC 5126 §4.
//
// Counter-signer, birinci imzacının SignerInfo.signature (OCTET STRING content
// octets) üzerine imza atar. Sonuç, orijinal SignerInfo'nun unsignedAttrs
// koleksiyonuna `id-countersignature` (1.2.840.113549.1.9.6) attribute olarak
// eklenir. Attribute değeri = "SignerInfo" — yani kendi içinde tam bir imzacı
// yapısı vardır.
//
// Counter-signer SignedAttrs:
//   - messageDigest (hash of outer.signature)  — zorunlu
//   - signingTime                               — opsiyonel
//   - signingCertificateV2                      — zorunlu (RFC 5126)
//   - contentType  — YOK (spec explicit excludes; counter-sig content signing değil)
//
// MA3 referans: ma3api-cmssignature Signer.addCounterSigner(ESignatureType,
// ECertificate, BaseSigner, attrs, params). Bizde cadesSign CMS core'unu
// yeniden kullanmıyoruz (contentType zorunlu oradaki flow) — ayrı minimal
// yolla SignerInfo üretiyoruz.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
	buildMessageDigestAttr,
	buildSigningCertificateV2Attr,
	buildSigningTimeAttr,
} from "./cades-attributes.ts";
import { CONTENT_TYPE, HASH_OID, SIG_ALG_OID, SIGNED_ATTR } from "./cades-constants.ts";
import { digest, type HashAlg, type SignatureAlg } from "./crypto.ts";
import { resolveSigner, type SignerInput } from "./sign.ts";

export type CadesCounterSignOptions = {
	/** Zaten imzalanmış CAdES SignedData (ContentInfo DER) */
	cms: Uint8Array;
	signer: SignerInput;
	digestAlgorithm?: HashAlg;
	signatureAlgorithm?: SignatureAlg;
	signingTime?: Date | null;
};

/**
 * Verilen CMS'in ilk SignerInfo'suna bir counter-signature ekler, yeni CMS döner.
 * Dış imza (ve mesaj içeriği) değişmez.
 */
export async function cadesCounterSign(opts: CadesCounterSignOptions): Promise<Uint8Array> {
	const resolved = await resolveSigner(opts);
	const digestAlg = opts.digestAlgorithm ?? "SHA-256";

	const asn = asn1js.fromBER(toAB(opts.cms));
	if (asn.offset === -1) throw new Error("cadesCounterSign: ASN.1 parse hatası");
	const ci = new pkijs.ContentInfo({ schema: asn.result });
	if (ci.contentType !== CONTENT_TYPE.signedData) {
		throw new Error(`cadesCounterSign: contentType signedData değil: ${ci.contentType}`);
	}
	const sd = new pkijs.SignedData({ schema: ci.content });
	if (sd.signerInfos.length === 0) throw new Error("cadesCounterSign: signerInfo yok");
	const outer = sd.signerInfos[0]!;

	// Outer imza bayt dizisi — counter-signer bunun hash'ini imzalayacak.
	const outerSigBytes = new Uint8Array(outer.signature.valueBlock.valueHexView);
	const msgDigest = await digest(digestAlg, outerSigBytes);

	const cert = new pkijs.Certificate({ schema: asn1js.fromBER(toAB(resolved.certificate)).result });

	// Counter-signer signedAttrs (RFC 5126 §4 — contentType YOK)
	const signedAttrs: pkijs.Attribute[] = [
		buildMessageDigestAttr(msgDigest),
		await buildSigningCertificateV2Attr(resolved.certificate, digestAlg),
	];
	if (opts.signingTime !== null) {
		signedAttrs.push(buildSigningTimeAttr(opts.signingTime ?? new Date()));
	}

	const counterSignerInfo = new pkijs.SignerInfo({
		version: 1,
		sid: new pkijs.IssuerAndSerialNumber({
			issuer: cert.issuer,
			serialNumber: cert.serialNumber,
		}),
		digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: HASH_OID[digestAlg] }),
		signedAttrs: new pkijs.SignedAndUnsignedAttributes({ type: 0, attributes: signedAttrs }),
	});

	// SignedAttrs SET DER → imza
	const attrsSet = new asn1js.Set({ value: signedAttrs.map((a) => a.toSchema()) });
	const sigBytes = await resolved.sign(new Uint8Array(attrsSet.toBER()));
	counterSignerInfo.signature = new asn1js.OctetString({ valueHex: toAB(sigBytes) });
	counterSignerInfo.signatureAlgorithm = new pkijs.AlgorithmIdentifier({
		algorithmId: SIG_ALG_OID[resolved.sigAlg],
	});

	// countersignature attribute = SignerInfo (RFC 5652 §11.4).
	const counterAttr = new pkijs.Attribute({
		type: SIGNED_ATTR.countersignature,
		values: [counterSignerInfo.toSchema()],
	});

	// Outer signerInfo'nun unsignedAttrs'ına ekle (imzalı değişmiyor).
	if (!outer.unsignedAttrs) {
		outer.unsignedAttrs = new pkijs.SignedAndUnsignedAttributes({ type: 1, attributes: [counterAttr] });
	} else {
		outer.unsignedAttrs.attributes = [...outer.unsignedAttrs.attributes, counterAttr];
	}

	// Counter-signer cert'ini SignedData.certificates'a ekle (yoksa). Verifier
	// zincirde bulabilsin diye.
	const certs = sd.certificates ?? [];
	certs.push(cert);
	sd.certificates = certs;

	const out = new pkijs.ContentInfo({
		contentType: CONTENT_TYPE.signedData,
		content: sd.toSchema(true),
	});
	return new Uint8Array(out.toSchema().toBER());
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
