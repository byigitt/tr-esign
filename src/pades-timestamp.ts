// PAdES-LTA DocTimeStamp. ETSI EN 319 142-1 §5.5.
//
// PAdES-LT PDF'e ikinci bir /Sig dictionary eklenir:
//   /Filter /Adobe.PPKLite
//   /SubFilter /ETSI.RFC3161
//   /Contents <HEX>  — RFC 3161 TimeStampToken (CMS değil, direkt TSP token)
//   /ByteRange [0 b c d]  — tüm önceki PDF + incremental update (hariç /Contents)
//
// Akış padesSign ile paralel ama CMS imza yerine RFC 3161 timestamp kullanılır:
// addSignaturePlaceholder(subFilter:ETSI.RFC3161) → ByteRange hash → TSA → splice.
//
// Not: Spec /Type /DocTimeStamp ister; @signpdf /Type /Sig yazar. Adobe/DSS/MA3
// çoğu verifier ikisini de kabul eder; strict ETSI compliance için v0.5.x'te
// /Type manipülasyonu (length-preserving) eklenebilir.

import { digest, type HashAlg } from "./crypto.ts";
import {
	addSignaturePlaceholder,
	extractByteRangeBytes,
	readByteRange,
	spliceSignature,
	SUBFILTER_ETSI_RFC3161,
} from "./pades-core.ts";
import { getTimestamp } from "./tsp.ts";

export type DocTimeStampOptions = {
	tsa?: { url?: string; policyOid?: string };
	digestAlgorithm?: HashAlg;
	signatureSize?: number;
};

export async function addDocTimeStamp(pdf: Uint8Array, opts: DocTimeStampOptions = {}): Promise<Uint8Array> {
	const withPlaceholder = addSignaturePlaceholder(pdf, {
		reason: "Document Timestamp",
		signerName: "DocTimeStamp",
		subFilter: SUBFILTER_ETSI_RFC3161,
		...(opts.signatureSize !== undefined && { signatureSize: opts.signatureSize }),
	});

	const br = readByteRange(withPlaceholder);
	const data = extractByteRangeBytes(withPlaceholder, br);
	const hashAlg = opts.digestAlgorithm ?? "SHA-256";
	const d = await digest(hashAlg, data);
	const ts = await getTimestamp({
		digest: d,
		digestAlgorithm: hashAlg,
		...(opts.tsa?.url !== undefined && { tsaUrl: opts.tsa.url }),
		...(opts.tsa?.policyOid !== undefined && { policyOid: opts.tsa.policyOid }),
	});

	// /Contents = RFC 3161 TimeStampToken (ContentInfo DER). CMS imza değil.
	return spliceSignature(withPlaceholder, ts.token);
}
