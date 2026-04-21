# reference/ — MA3 test fixture generator

Tek amaç: MA3 Java kütüphanesi ile **referans XAdES imzaları** üretmek. tr-esign
TypeScript implementasyonu bu imzalarla cross-verify edilir.

- `driver/Ma3Ref.java` — imzalayıcı + runtime OID dump
- `driver/Ma3Verify.java` — tr-esign çıktısını MA3 ile doğrula (ters yön)
- `gen-test-ca.sh` — openssl ile 3-katmanlı test CA hiyerarşisi üretir
- `fixtures/` — test input'ları (`test.p12` self-signed, `sample-invoice.xml`,
  opsiyonel `test-chain.p12` gerçek-zincirli)
- `lib/` — MA3 jar'ları (**git'te yok**; `/tmp/ma3-esign/java/lib/*.jar` kopyalanır)
- `out/` — üretilen imzalı XML'ler + `meta.json`

## CAdES + PAdES fixture — bilinen sınırlama

MA3'ün `BaseSignedData.addSigner()` (CAdES) ve `PAdESContainer.sign()`
(PAdES) metotları **online revocation kontrolü** yapıyor.
`P_VALIDATION_WITHOUT_FINDERS=true` + empty `P_ALL_CRLS` + empty
`P_ALL_BASIC_OCSP_RESPONSES` verilse bile iten stack:
`CertificateStatusInfo.getCertificate()` NPE (CAdES) veya
"Hiç güvenilir kök bulunamadı" (PAdES). Test CA placeholder OCSP/CDP
URL'lerine ulaşılamıyor.

Çözüm yolları (v0.5+):
- `docker run openssl ocsp -index ca.db -CA root.pem -rsigner responder.pem
  -port 8080` ile yerel responder
- Gerçek TR mali mühür PFX (üretim)
- `Ma3Verify.java`'yı CAdES/PAdES verify için genişletip **ters yön**
  cross-verify (tr-esign çıktısını MA3 doğrular)

Bugun:
- `cades-cross-verify.test.ts` `reference/out/cades-bes.p7s` varsa doğrular
- PAdES için benzer conditional test `pades-cross-verify.test.ts` v0.5.x'e.

tr-esign'ın CAdES/PAdES çıktısı RFC 5652/5035/3161, ETSI TS 101 733 ve
EN 319 142-1 (§5.3/5.4/5.5) uyumlu; kendi round-trip'i (sign ↔ verify)
tam. XAdES interop MA3 ile iki yönlü kanıtlı.

## Kurulum

```bash
# 1) MA3 JAR'larını ve lisans dosyasını kopyala (indirilen MA3 paketinden)
cp /tmp/ma3-esign/java/lib/*.jar reference/lib/
cp /tmp/ma3-esign/java/lisans/lisans.xml reference/fixtures/

# 2) Test keystore oluştur
cd reference/fixtures
keytool -genkeypair -alias testsigner -keyalg RSA -keysize 2048 \
  -sigalg SHA256withRSA -dname "CN=Test Signer, O=tr-esign test, C=TR" \
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
