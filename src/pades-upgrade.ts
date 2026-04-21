// PAdES seviye yükseltici.
//
// to:"T"   — PDF'ten CMS'i çıkar → cadesUpgrade({to:"T"}) → splice. §5.3.
// to:"LT"  — DSS dict incremental update (/Certs /CRLs /OCSPs streams +
//             güncel Root). §5.4.
// to:"LTA" — DocTimeStamp üzerine incremental: yeni /Sig dict /SubFilter
//             /ETSI.RFC3161 + ByteRange + TSA token. §5.5.

import { cadesUpgrade } from "./cades-upgrade.ts";
import { addDss } from "./pades-dss.ts";
import { addDocTimeStamp } from "./pades-timestamp.ts";
import { extractCms, spliceSignature } from "./pades-core.ts";

export type PadesUpgradeOptions =
	| { pdf: Uint8Array; to: "T"; tsa?: { url?: string; policyOid?: string } }
	| { pdf: Uint8Array; to: "LT"; chain: Uint8Array[]; crls?: Uint8Array[]; ocsps?: Uint8Array[] }
	| { pdf: Uint8Array; to: "LTA"; tsa?: { url?: string; policyOid?: string } };

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
	if (opts.to === "LT") {
		return addDss(opts.pdf, {
			certs: opts.chain,
			...(opts.crls && { crls: opts.crls }),
			...(opts.ocsps && { ocsps: opts.ocsps }),
		});
	}
	// to: "LTA"
	return addDocTimeStamp(opts.pdf, { ...(opts.tsa !== undefined && { tsa: opts.tsa }) });
}
