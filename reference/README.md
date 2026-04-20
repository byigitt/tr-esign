# reference/ — MA3 test fixture generator

Tek amaç: MA3 Java kütüphanesi ile **referans XAdES imzaları** üretmek. tr-xades
TypeScript implementasyonu bu imzalarla cross-verify edilir.

- `driver/Ma3Ref.java` — imzalayıcı + runtime OID dump
- `fixtures/` — test input'ları (`test.p12` self-signed RSA, `sample-invoice.xml`)
- `lib/` — MA3 jar'ları (**git'te yok**; `/tmp/ma3-esign/java/lib/*.jar` kopyalanır)
- `out/` — üretilen imzalı XML'ler + `meta.json`

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
