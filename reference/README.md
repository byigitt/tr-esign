# reference/ — MA3 test fixture generator

Tek amaç: MA3 Java kütüphanesi ile **referans XAdES imzaları** üretmek. tr-xades
TypeScript implementasyonu bu imzalarla cross-verify edilir.

- `driver/Ma3Ref.java` — imzalayıcı + runtime OID dump
- `driver/Ma3Verify.java` — tr-xades çıktısını MA3 ile doğrula (ters yön)
- `gen-test-ca.sh` — openssl ile 3-katmanlı test CA hiyerarşisi üretir
- `fixtures/` — test input'ları (`test.p12` self-signed, `sample-invoice.xml`,
  opsiyonel `test-chain.p12` gerçek-zincirli)
- `lib/` — MA3 jar'ları (**git'te yok**; `/tmp/ma3-esign/java/lib/*.jar` kopyalanır)
- `out/` — üretilen imzalı XML'ler + `meta.json`

## CAdES fixture — bilinen sınırlama

MA3'ün `BaseSignedData.addSigner()` metodu CAdES-BES için bile **online
revocation kontrolü** yapıyor. `P_VALIDATION_WITHOUT_FINDERS=true` +
empty `P_ALL_CRLS` + empty `P_ALL_BASIC_OCSP_RESPONSES` verilse bile iten
stack: `CertificateStatusInfo.getCertificate()` NPE. Test CA placeholder
OCSP/CDP URL'lerine ulaşılamıyor.

Çözüm yolları (v0.5+):
- `docker run openssl ocsp -index ca.db -CA root.pem -rsigner responder.pem
  -port 8080` ile yerel responder
- Gerçek TR mali mühür PFX (üretim)
- `Ma3Verify.java`'yı CAdES verify için genişletip **ters yön** cross-verify

Bugun: `cades-cross-verify.test.ts` `reference/out/cades-bes.p7s` var mı diye
bakıyor; yoksa skip ediyor. tr-xades CAdES sign ↔ verify kendi round-trip'i
spec-compliant (RFC 5652 / RFC 5035 / ETSI TS 101 733) olduğu için
imza üretimi ve doğrulama güvenilir. XAdES interop tam kanıtlı.

## Kurulum

```bash
# 1) MA3 JAR'larını ve lisans dosyasını kopyala (indirilen MA3 paketinden)
cp /tmp/ma3-esign/java/lib/*.jar reference/lib/
cp /tmp/ma3-esign/java/lisans/lisans.xml reference/fixtures/

# 2) Test keystore oluştur
cd reference/fixtures
keytool -genkeypair -alias testsigner -keyalg RSA -keysize 2048 \
  -sigalg SHA256withRSA -dname "CN=Test Signer, O=tr-xades test, C=TR" \
  -validity 3650 -keystore test.p12 -storetype PKCS12 \
  -storepass testpass -keypass testpass
```

MA3 paketini [https://yazilim.kamusm.gov.tr/?q=tr/ma3-e-imza-kütüphaneleri](https://yazilim.kamusm.gov.tr/?q=tr/ma3-e-imza-kütüphaneleri)
adresinden indirdiğiniz varsayılır. `lisans.xml` pakette `lisans/` dizininde
"Genel Kullanım" (tarihli) olarak geçiyor.

## Çalıştırma

```bash
./reference/run.sh
```

Çıktılar: `reference/out/enveloped-bes.xml`, `enveloping-bes.xml`,
`detached-bes.xml`, `enveloped-epes.xml`, `meta.json`.

## Nasıl kullanılır (TS tarafında)

TS kütüphanesi `test/cross-verify.test.ts` içinde `reference/out/*.xml`'i okur,
kendi verifier'ıyla doğrular. Tersine: TS `sign()` çıktısını MA3 verifier ile
doğrulamak için `Ma3Verify.java` (TBD) eklenebilir.
