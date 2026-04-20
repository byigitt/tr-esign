// RFC 6960 OCSP istemcisi.
//
// Tek `checkOcsp({certificate, issuer, responderUrl?, nonce?})` fonksiyonu.
// Responder URL verilmezse hedef cert'in AIA (AuthorityInfoAccess) extension'ından
// çekilir. Cevap raw DER olarak tutulur (XAdES-LT EncapsulatedOCSPValue için).

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

export type OcspStatus = "good" | "revoked" | "unknown";

export type OcspResult = {
	status: OcspStatus;
	response: Uint8Array; // DER OCSPResponse bytes
	producedAt: Date;
	thisUpdate: Date;
	nextUpdate?: Date;
	revokedAt?: Date;
	revocationReason?: number; // RFC 5280 CRLReason enum
	responderUrl: string;
};

export type OcspOptions = {
	certificate: Uint8Array;
	issuer: Uint8Array;
	responderUrl?: string;
	nonce?: Uint8Array;
};

export async function checkOcsp(o: OcspOptions): Promise<OcspResult> {
	const cert = parseCert(o.certificate);
	const issuer = parseCert(o.issuer);
	const url = o.responderUrl ?? ocspUrlFromAIA(cert);
	if (!url) throw new Error("OCSP responder URL bulunamadı (AIA yok veya responderUrl verilmedi)");

	const reqBytes = await buildRequest(cert, issuer, o.nonce);
	const resp = await fetch(url, {
		method: "POST",
		headers: { "Content-Type": "application/ocsp-request" },
		body: reqBytes as BodyInit,
	});
	if (!resp.ok) throw new Error(`OCSP HTTP ${resp.status}`);
	const respBytes = new Uint8Array(await resp.arrayBuffer());
	return parseOcspResponse(respBytes, url);
}

export function ocspUrlFromAIA(cert: pkijs.Certificate): string | null {
	const aia = cert.extensions?.find((e) => e.extnID === "1.3.6.1.5.5.7.1.1");
	if (!aia?.parsedValue) return null;
	const parsed = aia.parsedValue as pkijs.InfoAccess;
	const ocsp = parsed.accessDescriptions.find((ad) => ad.accessMethod === "1.3.6.1.5.5.7.48.1");
	const loc = ocsp?.accessLocation;
	// accessLocation is a GeneralName; for URL it's type 6 (uniformResourceIdentifier).
	// pkijs represents it as asn1js.Constructed with valueBlock containing IA5String.
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const s = (loc as any)?.value?.valueBlock?.value;
	return typeof s === "string" ? s : null;
}

export async function buildRequest(
	cert: pkijs.Certificate,
	issuer: pkijs.Certificate,
	nonce?: Uint8Array,
): Promise<Uint8Array> {
	const req = new pkijs.OCSPRequest();
	await req.createForCertificate(cert, {
		hashAlgorithm: "SHA-256",
		issuerCertificate: issuer,
	});
	const n = nonce ?? randomNonce();
	// RFC 6960 §4.4.1 Nonce Extension (id-pkix-ocsp-nonce = 1.3.6.1.5.5.7.48.1.2).
	req.tbsRequest.requestExtensions = [
		new pkijs.Extension({
			extnID: "1.3.6.1.5.5.7.48.1.2",
			extnValue: new asn1js.OctetString({ valueHex: n.buffer as ArrayBuffer }).toBER(false),
		}),
	];
	return new Uint8Array(req.toSchema(true).toBER());
}

export function parseOcspResponse(bytes: Uint8Array, url: string): OcspResult {
	const asn = asn1js.fromBER(toAB(bytes));
	if (asn.offset === -1) throw new Error("OCSP response: ASN.1 parse hatası");
	const resp = new pkijs.OCSPResponse({ schema: asn.result });

	if (resp.responseStatus.valueBlock.valueDec !== 0) {
		throw new Error(`OCSP responseStatus=${resp.responseStatus.valueBlock.valueDec}`);
	}
	if (!resp.responseBytes) throw new Error("OCSP cevabı basic response içermiyor");

	const basic = new pkijs.BasicOCSPResponse({
		schema: asn1js.fromBER(toAB(new Uint8Array(resp.responseBytes.response.valueBlock.valueHexView))).result,
	});
	const single = basic.tbsResponseData.responses[0];
	if (!single) throw new Error("OCSP tbsResponseData boş");

	// certStatus CHOICE: [0]GoodInfo (NULL), [1]RevokedInfo (SEQUENCE), [2]UnknownInfo (NULL)
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const cs = single.certStatus as any;
	const tag = cs?.idBlock?.tagNumber;
	let status: OcspStatus;
	let revokedAt: Date | undefined;
	let revocationReason: number | undefined;
	if (tag === 0) status = "good";
	else if (tag === 1) {
		status = "revoked";
		// RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT CRLReason OPTIONAL }
		// pkijs has no wrapper; parse inline.
		const items = cs.valueBlock?.value ?? [];
		if (items[0]) revokedAt = new Date(items[0].valueBlock.toDate());
		if (items[1]?.valueBlock?.value?.[0]) {
			revocationReason = items[1].valueBlock.value[0].valueBlock.valueDec;
		}
	} else status = "unknown";

	return {
		status,
		response: bytes,
		producedAt: basic.tbsResponseData.producedAt,
		thisUpdate: single.thisUpdate,
		nextUpdate: single.nextUpdate,
		...(revokedAt ? { revokedAt } : {}),
		...(revocationReason !== undefined ? { revocationReason } : {}),
		responderUrl: url,
	};
}

function parseCert(der: Uint8Array): pkijs.Certificate {
	return new pkijs.Certificate({ schema: asn1js.fromBER(toAB(der)).result });
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}

function randomNonce(): Uint8Array {
	const u = new Uint8Array(16);
	globalThis.crypto.getRandomValues(u);
	return u;
}
