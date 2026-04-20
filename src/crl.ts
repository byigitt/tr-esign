// X.509 CRL (RFC 5280 §5) indir + parse + sorgula. Sunulan her şey saf veri
// olduğu için çağrıcı isterse bytes'ı cache'leyip parseCrl()'e verir —
// kütüphane kendi cache'ini tutmaz.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

export type Crl = {
	der: Uint8Array; // EncapsulatedCRLValue base64 payload'ı için
	thisUpdate: Date;
	nextUpdate?: Date;
	issuerLdap: string; // DN string; zincir eşlemesinde kullanılır
	revoked: Map<string, { date: Date; reason?: number }>; // serialHex (lowercase) → info
};

export async function fetchCrl(url: string): Promise<Uint8Array> {
	const r = await fetch(url);
	if (!r.ok) throw new Error(`CRL HTTP ${r.status} @ ${url}`);
	return new Uint8Array(await r.arrayBuffer());
}

export function parseCrl(der: Uint8Array): Crl {
	const asn = asn1js.fromBER(toAB(der));
	if (asn.offset === -1) throw new Error("CRL: ASN.1 parse hatası");
	const crl = new pkijs.CertificateRevocationList({ schema: asn.result });

	const revoked = new Map<string, { date: Date; reason?: number }>();
	for (const r of crl.revokedCertificates ?? []) {
		const serialHex = toHex(new Uint8Array(r.userCertificate.valueBlock.valueHexView));
		const info: { date: Date; reason?: number } = { date: r.revocationDate.value };
		// CRL entry extensions: CRLReason (id-ce-cRLReasons = 2.5.29.21)
		const reasonExt = r.crlEntryExtensions?.extensions.find((e) => e.extnID === "2.5.29.21");
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const enumeratedReason = (reasonExt?.parsedValue as any)?.valueBlock?.valueDec;
		if (typeof enumeratedReason === "number") info.reason = enumeratedReason;
		revoked.set(serialHex, info);
	}

	return {
		der,
		thisUpdate: crl.thisUpdate.value,
		...(crl.nextUpdate ? { nextUpdate: crl.nextUpdate.value } : {}),
		issuerLdap: dnToLdap(crl.issuer),
		revoked,
	};
}

export function isRevoked(crl: Crl, serialHex: string): { date: Date; reason?: number } | null {
	return crl.revoked.get(serialHex.toLowerCase()) ?? null;
}

// CRL Distribution Points extension (2.5.29.31). Birden çok URL dönebilir.
export function crlUrlsFromCert(certDer: Uint8Array): string[] {
	const cert = new pkijs.Certificate({ schema: asn1js.fromBER(toAB(certDer)).result });
	const ext = cert.extensions?.find((e) => e.extnID === "2.5.29.31");
	if (!ext?.parsedValue) return [];
	const cdp = ext.parsedValue as pkijs.CRLDistributionPoints;
	const out: string[] = [];
	for (const dp of cdp.distributionPoints ?? []) {
		const fullName = dp.distributionPoint;
		if (!Array.isArray(fullName)) continue;
		for (const gn of fullName) {
			// GeneralName URI (type 6, IA5String)
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const s = (gn as any)?.value?.valueBlock?.value;
			if (typeof s === "string") out.push(s);
		}
	}
	return out;
}

function toHex(u8: Uint8Array): string {
	return Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("").toLowerCase();
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function dnToLdap(name: any): string {
	const map: Record<string, string> = {
		"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU",
		"2.5.4.7": "L", "2.5.4.8": "ST", "1.2.840.113549.1.9.1": "E",
	};
	return name.typesAndValues
		.map((tv: { type: string; value: { valueBlock: { value: string } } }) =>
			`${map[tv.type] ?? tv.type}=${tv.value.valueBlock.value}`)
		.reverse()
		.join(",");
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
