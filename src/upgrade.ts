// XAdES seviye yükseltici. BES/EPES → T (sonraki fazlarda LT/LTA).
//
// XAdES-T (ETSI TS 101 903 §7.3): SignatureTimeStamp, ds:SignatureValue'un
// canonicalize edilmiş hali üzerinde RFC 3161 timestamp. EncapsulatedTimeStamp
// base64 CMS TimeStampToken içerir. xades:UnsignedProperties/UnsignedSignatureProperties
// zinciri yoksa oluşturulur.

import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { canonicalize, c14nAlgFromUri, type C14NAlg } from "./c14n.ts";
import { C14N, NS } from "./constants.ts";
import { digest, type HashAlg } from "./crypto.ts";
import { makeId } from "./ids.ts";
import { getTimestamp } from "./tsp.ts";

export type UpgradeOptions = {
	xml: string;
	to: "T"; // LT/LTA sonraki fazlarda
	tsa?: { url?: string; policyOid?: string };
	digestAlgorithm?: HashAlg; // default SHA-256
	c14nAlgorithm?: C14NAlg; // default: SignedInfo'nun CanonicalizationMethod'undan
};

export async function upgrade(opts: UpgradeOptions): Promise<string> {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const doc: any = new DOMParser().parseFromString(opts.xml, "text/xml");
	const sig = first(doc, NS.ds, "Signature");
	if (!sig) throw new Error("ds:Signature bulunamadı");
	const sv = firstChild(sig, NS.ds, "SignatureValue");
	if (!sv) throw new Error("ds:SignatureValue bulunamadı");

	const c14nAlg = opts.c14nAlgorithm ?? detectC14n(sig);
	const hashAlg = opts.digestAlgorithm ?? "SHA-256";

	const d = await digest(hashAlg, canonicalize(sv, c14nAlg));
	const ts = await getTimestamp({
		digest: d,
		digestAlgorithm: hashAlg,
		tsaUrl: opts.tsa?.url,
		policyOid: opts.tsa?.policyOid,
	});

	const stEl = doc.createElementNS(NS.xades, "xades:SignatureTimeStamp");
	stEl.setAttribute("Id", makeId("Signature-TimeStamp"));
	const cm = doc.createElementNS(NS.ds, "ds:CanonicalizationMethod");
	cm.setAttribute("Algorithm", C14N[c14nAlg]);
	stEl.appendChild(cm);
	const ets = doc.createElementNS(NS.xades, "xades:EncapsulatedTimeStamp");
	ets.appendChild(doc.createTextNode(Buffer.from(ts.token).toString("base64")));
	stEl.appendChild(ets);

	const qp = first(sig, NS.xades, "QualifyingProperties");
	if (!qp) throw new Error("xades:QualifyingProperties bulunamadı");
	const usprops = ensureUnsignedSignatureProperties(doc, qp);
	usprops.appendChild(stEl);

	return new XMLSerializer().serializeToString(doc);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ensureUnsignedSignatureProperties(doc: any, qp: any): any {
	let uprops = firstChild(qp, NS.xades, "UnsignedProperties");
	if (!uprops) {
		uprops = doc.createElementNS(NS.xades, "xades:UnsignedProperties");
		qp.appendChild(uprops);
	}
	let usprops = firstChild(uprops, NS.xades, "UnsignedSignatureProperties");
	if (!usprops) {
		usprops = doc.createElementNS(NS.xades, "xades:UnsignedSignatureProperties");
		uprops.appendChild(usprops);
	}
	return usprops;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function detectC14n(sig: any): C14NAlg {
	const si = first(sig, NS.ds, "SignedInfo");
	const cm = si ? firstChild(si, NS.ds, "CanonicalizationMethod") : null;
	const uri = cm?.getAttribute("Algorithm");
	if (!uri) throw new Error("SignedInfo'da CanonicalizationMethod bulunamadı");
	return c14nAlgFromUri(uri);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function first(parent: any, ns: string, local: string): any {
	return parent.getElementsByTagNameNS(ns, local).item(0);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function firstChild(parent: any, ns: string, local: string): any {
	for (let n = parent.firstChild; n; n = n.nextSibling) {
		if (n.nodeType === 1 && n.namespaceURI === ns && n.localName === local) return n;
	}
	return null;
}
