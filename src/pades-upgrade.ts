// PAdES seviye yükseltici.
//
// to:"T"  — Akış: PDF'ten CMS'i çıkar → cadesUpgrade({to:"T"}) → /Contents
//            placeholder'a yeni CMS'i yaz (length-preserving).
// to:"LT" — DSS dict incremental update — /Certs /CRLs /OCSPs streams +
//            güncel Root. ETSI EN 319 142-1 §5.4.
// LTA sonraki iterasyona (DocTimeStamp ayrı /Sig dict, §5.5).

import { cadesUpgrade } from "./cades-upgrade.ts";
import { addDss } from "./pades-dss.ts";
import { extractCms, spliceSignature } from "./pades-core.ts";

export type PadesUpgradeOptions =
	| { pdf: Uint8Array; to: "T"; tsa?: { url?: string; policyOid?: string } }
	| { pdf: Uint8Array; to: "LT"; chain: Uint8Array[]; crls?: Uint8Array[]; ocsps?: Uint8Array[] };

export async function padesUpgrade(opts: PadesUpgradeOptions): Promise<Uint8Array> {
	if (opts.to === "T") {
		const cms = extractCms(opts.pdf);
		const upgraded = await cadesUpgrade({
			bytes: cms,
			to: "T",
			...(opts.tsa !== undefined && { tsa: opts.tsa }),
		});
		return spliceSignature(opts.pdf, upgraded);
	}
	// to: "LT"
	return addDss(opts.pdf, {
		certs: opts.chain,
		...(opts.crls && { crls: opts.crls }),
		...(opts.ocsps && { ocsps: opts.ocsps }),
	});
}
