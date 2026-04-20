// XAdES seviye yükseltici. BES/EPES → T → LT (→ LTA faz 7.5).
//
// Tek `upgrade()` fonksiyonu, to parametresine göre davranış:
//   to:"T"  → SignatureTimeStamp ekle (ETSI TS 101 903 §7.3)
//   to:"LT" → CertificateValues + RevocationValues ekle (§ XAdES-X-L pattern).
// Level cascading yok — kullanıcı hedeflediği seviyeye göre sırayla çağırır.
// LT çağrısı T'yi otomatik eklemez; amaç saf ek yapılması (her upgrade tek iş).

import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { canonicalize, c14nAlgFromUri, type C14NAlg } from "./c14n.ts";
import { C14N, NS } from "./constants.ts";
import { digest, type HashAlg } from "./crypto.ts";
import { makeId } from "./ids.ts";
import { getTimestamp } from "./tsp.ts";

export type UpgradeOptions =
	| { xml: string; to: "T"; tsa?: { url?: string; policyOid?: string }; digestAlgorithm?: HashAlg; c14nAlgorithm?: C14NAlg }
	| { xml: string; to: "LT"; chain: Uint8Array[]; crls?: Uint8Array[]; ocsps?: Uint8Array[] };

export async function upgrade(opts: UpgradeOptions): Promise<string> {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const doc: any = new DOMParser().parseFromString(opts.xml, "text/xml");
	const sig = first(doc, NS.ds, "Signature");
	if (!sig) throw new Error("ds:Signature bulunamadı");
	const qp = first(sig, NS.xades, "QualifyingProperties");
	if (!qp) throw new Error("xades:QualifyingProperties bulunamadı");
	const usprops = ensureUnsignedSignatureProperties(doc, qp);

	if (opts.to === "T") await addSignatureTimeStamp(doc, sig, usprops, opts);
	else if (opts.to === "LT") addLongTermValues(doc, usprops, opts);

	return new XMLSerializer().serializeToString(doc);
}

// ---- XAdES-T ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function addSignatureTimeStamp(doc: any, sig: any, usprops: any, o: Extract<UpgradeOptions, { to: "T" }>): Promise<void> {
	const sv = firstChild(sig, NS.ds, "SignatureValue");
	if (!sv) throw new Error("ds:SignatureValue bulunamadı");
	const c14nAlg = o.c14nAlgorithm ?? detectC14n(sig);
	const hashAlg = o.digestAlgorithm ?? "SHA-256";

	const d = await digest(hashAlg, canonicalize(sv, c14nAlg));
	const ts = await getTimestamp({
		digest: d,
		digestAlgorithm: hashAlg,
		tsaUrl: o.tsa?.url,
		policyOid: o.tsa?.policyOid,
	});

	const st = doc.createElementNS(NS.xades, "xades:SignatureTimeStamp");
	st.setAttribute("Id", makeId("Signature-TimeStamp"));
	const cm = doc.createElementNS(NS.ds, "ds:CanonicalizationMethod");
	cm.setAttribute("Algorithm", C14N[c14nAlg]);
	st.appendChild(cm);
	const ets = doc.createElementNS(NS.xades, "xades:EncapsulatedTimeStamp");
	ets.appendChild(doc.createTextNode(Buffer.from(ts.token).toString("base64")));
	st.appendChild(ets);
	usprops.appendChild(st);
}

// ---- XAdES-LT ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function addLongTermValues(doc: any, usprops: any, o: Extract<UpgradeOptions, { to: "LT" }>): void {
	const cv = doc.createElementNS(NS.xades, "xades:CertificateValues");
	cv.setAttribute("Id", makeId("Certificate-Values"));
	for (const d of o.chain) cv.appendChild(encap(doc, "xades:EncapsulatedX509Certificate", d));
	usprops.appendChild(cv);

	const crls = o.crls ?? [];
	const ocsps = o.ocsps ?? [];
	if (crls.length === 0 && ocsps.length === 0) return;

	const rv = doc.createElementNS(NS.xades, "xades:RevocationValues");
	rv.setAttribute("Id", makeId("Revocation-Values"));
	if (crls.length) {
		const group = doc.createElementNS(NS.xades, "xades:CRLValues");
		for (const d of crls) group.appendChild(encap(doc, "xades:EncapsulatedCRLValue", d));
		rv.appendChild(group);
	}
	if (ocsps.length) {
		const group = doc.createElementNS(NS.xades, "xades:OCSPValues");
		for (const d of ocsps) group.appendChild(encap(doc, "xades:EncapsulatedOCSPValue", d));
		rv.appendChild(group);
	}
	usprops.appendChild(rv);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function encap(doc: any, qname: string, der: Uint8Array): any {
	const e = doc.createElementNS(NS.xades, qname);
	e.appendChild(doc.createTextNode(Buffer.from(der).toString("base64")));
	return e;
}

// ---- shared helpers ----

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
