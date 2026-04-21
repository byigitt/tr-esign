// MA3 verify driver — tr-esign'in ürettiği XML'leri MA3 ile doğrula (interop testi).
// Kullanım:  java -cp ".:../lib/*" Ma3Verify <xml-file>
// Çıkış kodu: 0 = valid, 1 = invalid, 2 = error.
// Stdout tek satır JSON: { "type": ..., "message": ... }

import java.io.File;
import java.io.FileInputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

import tr.gov.tubitak.uekae.esya.api.common.util.LicenseUtil;
import tr.gov.tubitak.uekae.esya.api.xmlsignature.Context;
import tr.gov.tubitak.uekae.esya.api.xmlsignature.SignedDocument;
import tr.gov.tubitak.uekae.esya.api.xmlsignature.ValidationResult;
import tr.gov.tubitak.uekae.esya.api.xmlsignature.XMLSignature;

public class Ma3Verify {
	public static void main(String[] args) throws Exception {
		if (args.length < 1) {
			System.err.println("Usage: Ma3Verify <xml-file>");
			System.exit(2);
		}
		String path = args[0];

		try (FileInputStream lis = new FileInputStream("../fixtures/lisans.xml")) {
			if (!LicenseUtil.setLicenseXml(lis)) {
				System.err.println("MA3 license load failed");
				System.exit(2);
			}
		}

		File f = new File(path);
		Context ctx = new Context(f.getAbsoluteFile().getParentFile());

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = dbf.newDocumentBuilder().parse(f);

		// XMLSignature.parse() tek imza; kökte ds:Signature varsa veya ilk
		// ds:Signature elemanını çeker. Enveloped'da root Invoice, enveloping'de
		// root ds:Signature — iki tarafta da çalışıyor.
		org.w3c.dom.Element sigEl = doc.getDocumentElement();
		if (!"Signature".equals(sigEl.getLocalName())) {
			org.w3c.dom.NodeList sigs = doc.getElementsByTagNameNS(
					"http://www.w3.org/2000/09/xmldsig#", "Signature");
			if (sigs.getLength() == 0) {
				System.err.println("No ds:Signature found");
				System.exit(2);
			}
			sigEl = (org.w3c.dom.Element) sigs.item(0);
		}

		XMLSignature sig = new XMLSignature(sigEl, ctx);
		ValidationResult r;
		try { r = sig.verify(); }
		catch (Exception e) {
			System.out.println(jsonObj("ERROR", e.getMessage()));
			System.exit(1);
			return;
		}
		String t = String.valueOf(r.getType());
		System.out.println(jsonObj(t, String.valueOf(r.getMessage())));
		System.exit("VALID".equals(t) ? 0 : 1);
	}

	static String jsonObj(String type, String message) {
		return "{\"type\":\"" + esc(type) + "\",\"message\":\"" + esc(message) + "\"}";
	}
	static String esc(String s) {
		if (s == null) return "";
		StringBuilder b = new StringBuilder();
		for (char c : s.toCharArray()) {
			switch (c) {
				case '"': b.append("\\\""); break;
				case '\\': b.append("\\\\"); break;
				case '\n': b.append("\\n"); break;
				case '\r': b.append("\\r"); break;
				case '\t': b.append("\\t"); break;
				default: b.append(c < 0x20 ? String.format("\\u%04x", (int) c) : c);
			}
		}
		return b.toString();
	}
}
