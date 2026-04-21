// CAdES-BES/EPES/T doğrulayıcı. pkijs.SignedData.verify() ile CMS-level imza
// bütünlüğü doğrulanır; seviye tespit signedAttrs/unsignedAttrs'e bakarak yapılır.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { CADES_ATTR, CONTENT_TYPE, SIGNED_ATTR } from "./cades-constants.ts";
import { certToSignerInfo, type Level, type SignerInfo as SignerInfoReport, type VerifyResult } from "./verify.ts";

export type CadesVerifyOptions = {
	detachedContent?: Uint8Array; // detached imzada dış veri
};

export async function cadesVerify(bytes: Uint8Array, opts: CadesVerifyOptions = {}): Promise<VerifyResult> {
	try {
		const asn = asn1js.fromBER(toAB(bytes));
		if (asn.offset === -1) return invalid("CAdES: ASN.1 parse hatası");
		const contentInfo = new pkijs.ContentInfo({ schema: asn.result });
		if (contentInfo.contentType !== CONTENT_TYPE.signedData) {
			return invalid(`CAdES: ContentType SignedData değil: ${contentInfo.contentType}`);
		}
		const sd = new pkijs.SignedData({ schema: contentInfo.content });
		if (sd.signerInfos.length !== 1) {
			return invalid(`CAdES: tek signerInfo bekleniyor, ${sd.signerInfos.length} var`);
		}

		// Attached data veya opts.detachedContent'ten doğrulama için bytes
		const eContent = sd.encapContentInfo.eContent;
		const dataAB = opts.detachedContent
			? toAB(opts.detachedContent)
			: eContent
				? eContent.valueBlock.valueHexView.slice().buffer
				: null;
		if (!dataAB) return invalid("CAdES: attached eContent veya detachedContent gerekli");

		// pkijs SignedData.verify — signature + messageDigest attribute tutarlılığı.
		// Başarı durumunda boolean true, başarısızlıkta ya false ya da hata fırlatır.
		const ok = await sd.verify({ signer: 0, data: dataAB });
		if (ok !== true) return invalid("CAdES: SignerInfo imzası doğrulanamadı");

		const si = sd.signerInfos[0]!;
		const signedAttrs = si.signedAttrs?.attributes ?? [];
		const unsignedAttrs = si.unsignedAttrs?.attributes ?? [];

		const signer = findSignerCert(sd, si);
		if (!signer) return invalid("CAdES: SignerInfo.sid ile eşleşen sertifika SignedData.certificates'ta yok");

		const counterSignatures = extractCounterSigners(unsignedAttrs, sd);
		return {
			valid: true,
			level: detectLevel(signedAttrs, unsignedAttrs),
			signer: certToSignerInfo(signer),
			...(extractSigningTime(signedAttrs) ? { signedAt: extractSigningTime(signedAttrs) } : {}),
			...(counterSignatures.length > 0 && { counterSignatures }),
		};
	} catch (e) {
		return invalid(e instanceof Error ? e.message : "unknown error", e);
	}
}

function detectLevel(signed: pkijs.Attribute[], unsigned: pkijs.Attribute[]): Level {
	const signedTypes = new Set(signed.map((a) => a.type));
	const unsignedTypes = new Set(unsigned.map((a) => a.type));
	if (unsignedTypes.has(CADES_ATTR.archiveTimeStampV2) || unsignedTypes.has(CADES_ATTR.archiveTimeStampV3)) return "LTA";
	if (unsignedTypes.has(CADES_ATTR.certValues) || unsignedTypes.has(CADES_ATTR.revocationValues)) return "LT";
	if (unsignedTypes.has(CADES_ATTR.signatureTimeStamp)) return "T";
	if (signedTypes.has(CADES_ATTR.signaturePolicyIdentifier)) return "EPES";
	return "BES";
}

function extractSigningTime(signed: pkijs.Attribute[]): Date | undefined {
	const a = signed.find((x) => x.type === "1.2.840.113549.1.9.5");
	if (!a || a.values.length === 0) return undefined;
	const v = a.values[0] as asn1js.UTCTime | asn1js.GeneralizedTime;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const d = (v as any).toDate?.() ?? (v as any).valueBlock?.toDate?.() ?? v.valueBlock.value;
	return d instanceof Date ? d : new Date(d);
}

/**
 * countersignature unsigned attribute(lar)ı çözüp counter-signer cert'lerini
 * rapor eder. RFC 5652 §11.4 — attribute value = SignerInfo. Counter-signer
 * sid'ini SignedData.certificates'ta arar.
 */
function extractCounterSigners(
	unsignedAttrs: pkijs.Attribute[],
	sd: pkijs.SignedData,
): SignerInfoReport[] {
	const out: SignerInfoReport[] = [];
	for (const attr of unsignedAttrs) {
		if (attr.type !== SIGNED_ATTR.countersignature) continue;
		for (const v of attr.values) {
			try {
				const siCs = new pkijs.SignerInfo({ schema: v });
				const cert = findSignerCert(sd, siCs);
				if (cert) out.push(certToSignerInfo(cert));
			} catch { /* ignore malformed counter-sig entry */ }
		}
	}
	return out;
}

function findSignerCert(sd: pkijs.SignedData, si: pkijs.SignerInfo): pkijs.Certificate | undefined {
	const sid = si.sid;
	if (!(sid instanceof pkijs.IssuerAndSerialNumber)) return undefined;
	const targetSerial = sid.serialNumber.valueBlock.toString();
	for (const c of sd.certificates ?? []) {
		if (!(c instanceof pkijs.Certificate)) continue;
		if (c.serialNumber.valueBlock.toString() === targetSerial) return c;
	}
	return undefined;
}

function invalid(reason: string, detail?: unknown): VerifyResult {
	return detail === undefined ? { valid: false, reason } : { valid: false, reason, detail };
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
