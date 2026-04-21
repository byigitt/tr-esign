// X.509 chain validation (RFC 5280 minimal, pkijs CertificateChainValidationEngine
// üstünde). Sertifika bundle'ı (TR Kamu SM kökleri vs.) kullanıcıdan gelir —
// redistribution/versioning sorunları yüzünden kütüphane kökleri embed etmez.
// loadKamuSmRoots() çalıştırma zamanında fetch eder.

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

export type ChainResult =
	| { valid: true; path: Uint8Array[] } // DER list, leaf → root
	| { valid: false; reason: string; code?: number };

export type ValidateOptions = {
	leaf: Uint8Array; // end-entity DER
	intermediates?: Uint8Array[];
	roots: Uint8Array[]; // trusted anchors
	checkDate?: Date;
	crls?: Uint8Array[];
	ocspResponses?: Uint8Array[];
};

export async function validateChain(o: ValidateOptions): Promise<ChainResult> {
	try {
		const leaf = parseCert(o.leaf);
		const intermediates = (o.intermediates ?? []).map(parseCert);
		const roots = o.roots.map(parseCert);
		const crls = (o.crls ?? []).map((d) => new pkijs.CertificateRevocationList({ schema: asn1js.fromBER(toAB(d)).result }));
		const ocsps = (o.ocspResponses ?? []).map((d) => {
			const resp = new pkijs.OCSPResponse({ schema: asn1js.fromBER(toAB(d)).result });
			if (!resp.responseBytes) throw new Error("OCSP cevabı basic response içermiyor");
			const basic = asn1js.fromBER(toAB(new Uint8Array(resp.responseBytes.response.valueBlock.valueHexView))).result;
			return new pkijs.BasicOCSPResponse({ schema: basic });
		});

		const engine = new pkijs.CertificateChainValidationEngine({
			certs: [leaf, ...intermediates],
			trustedCerts: roots,
			...(crls.length ? { crls } : {}),
			...(ocsps.length ? { ocsps } : {}),
			...(o.checkDate ? { checkDate: o.checkDate } : {}),
		});
		const r = await engine.verify();
		if (!r.result) return { valid: false, reason: r.resultMessage ?? "chain invalid", code: r.resultCode };
		const path = (r.certificatePath ?? []).map((c) => new Uint8Array(c.toSchema().toBER()));
		return { valid: true, path };
	} catch (e) {
		return { valid: false, reason: e instanceof Error ? e.message : String(e) };
	}
}

// Kamu SM SertifikaDeposu: runtime'da fetch + parse (güncel liste).
// Schema: <koksertifika><mValue>base64</mValue><mSubjectName/>...</koksertifika>.
export async function loadKamuSmRoots(
	url = "http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml",
): Promise<Uint8Array[]> {
	const r = await fetch(url);
	if (!r.ok) throw new Error(`Kamu SM deposu HTTP ${r.status}`);
	const xml = await r.text();
	const out: Uint8Array[] = [];
	const blockRe = /<koksertifika>([\s\S]*?)<\/koksertifika>/g;
	const valRe = /<mValue>\s*([A-Za-z0-9+/=\s]+?)\s*<\/mValue>/;
	for (const m of xml.matchAll(blockRe)) {
		const v = valRe.exec(m[1]!);
		if (!v) continue;
		const b64 = v[1]!.replace(/\s+/g, "");
		try { out.push(new Uint8Array(Buffer.from(b64, "base64"))); }
		catch { /* skip bad entry */ }
	}
	return out;
}

/**
 * Offline Kamu SM root snapshot — `reference/fetch-kamusm-roots.sh` çıktısı
 * `src/kamusm-roots-snapshot.ts`’den DER yükler. Bağımsız fetch gerekmez.
 * Güncelleme için script elle çalıştırılır; kok set nadir değişir.
 */
export async function loadKamuSmRootsOffline(): Promise<Uint8Array[]> {
	const mod = await import("./kamusm-roots-snapshot.ts");
	return mod.kamuSmRootsDer();
}

function parseCert(der: Uint8Array): pkijs.Certificate {
	return new pkijs.Certificate({ schema: asn1js.fromBER(toAB(der)).result });
}
function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}
