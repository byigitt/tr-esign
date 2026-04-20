// tr-xades e-Fatura örneği: UBL 2.1 + TR 1.2 temel fatura imzalanır + doğrulanır.
//
// Çalıştır:  pnpm run example:efatura
//
// Bu örnek, GİB UBL-TR 1.2 "TEMELFATURA" profili için yapısal olarak doğru
// bir Invoice iskeleti kullanır (tam legal bir fatura değildir — şema uyumu
// için tüm zorunlu alanlar olabilir eksik; yalnız imzalama akışını gösterir).

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { sign } from "../src/sign.ts";
import { verify } from "../src/verify.ts";

const root = join(import.meta.dirname, "..");
const pfx = new Uint8Array(readFileSync(join(root, "reference/fixtures/test.p12")));

const invoiceId = `TR${new Date().getFullYear()}${Math.floor(Math.random() * 1e9).toString().padStart(9, "0")}`;

// UBL-TR 1.2 TEMELFATURA iskeleti. ext:ExtensionContent boş bırakılır;
// tr-xades sign() ds:Signature'ı oraya yerleştirir.
const invoice = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionContent/>
    </ext:UBLExtension>
  </ext:UBLExtensions>
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>TR1.2</cbc:CustomizationID>
  <cbc:ProfileID>TEMELFATURA</cbc:ProfileID>
  <cbc:ID>${invoiceId}</cbc:ID>
  <cbc:UUID>${randomUUID()}</cbc:UUID>
  <cbc:IssueDate>${new Date().toISOString().slice(0, 10)}</cbc:IssueDate>
  <cbc:InvoiceTypeCode>SATIS</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>TRY</cbc:DocumentCurrencyCode>

  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="VKN">1234567890</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName><cbc:Name>ÖRNEK SATICI A.Ş.</cbc:Name></cac:PartyName>
    </cac:Party>
  </cac:AccountingSupplierParty>

  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="TCKN">11111111111</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName><cbc:Name>ÖRNEK ALICI</cbc:Name></cac:PartyName>
    </cac:Party>
  </cac:AccountingCustomerParty>

  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="TRY">18.00</cbc:TaxAmount>
    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="TRY">100.00</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="TRY">18.00</cbc:TaxAmount>
      <cac:TaxCategory><cac:TaxScheme><cbc:Name>KDV</cbc:Name><cbc:TaxTypeCode>0015</cbc:TaxTypeCode></cac:TaxScheme></cac:TaxCategory>
    </cac:TaxSubtotal>
  </cac:TaxTotal>

  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="TRY">100.00</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="TRY">100.00</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="TRY">118.00</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="TRY">118.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>

  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID>
    <cbc:InvoicedQuantity unitCode="NIU">1.0</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="TRY">100.00</cbc:LineExtensionAmount>
    <cac:Item><cbc:Name>Örnek Ürün</cbc:Name></cac:Item>
    <cac:Price><cbc:PriceAmount currencyID="TRY">100.00</cbc:PriceAmount></cac:Price>
  </cac:InvoiceLine>
</Invoice>`;

const signed = await sign({
	input: { xml: invoice, placement: "ubl-extension" },
	signer: { pfx, password: "testpass" },
	signingTime: new Date(),
	productionPlace: { city: "İstanbul", country: "TR" },
	commitmentType: "proof-of-origin",
});

const result = await verify(signed);
if (!result.valid) {
	console.error(`VERIFY FAILED: ${result.reason}`);
	process.exit(1);
}

console.error(`✓ Imzaland\u0131 + dogrulandi: level=${result.level} signer=${result.signer.subject}`);
console.error(`  boyut: ${signed.length} bytes`);
process.stdout.write(signed);
