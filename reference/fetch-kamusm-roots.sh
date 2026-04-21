#!/usr/bin/env bash
# Kamu SM SertifikaDeposu.xml'den root cert'leri indirir, PEM bundle çıkarır
# ve src/kamusm-roots-snapshot.ts dosyasını üretir (hard-coded PEM array).
#
# Kullanım:
#   bash reference/fetch-kamusm-roots.sh
#
# Bu kütüphane kendi sürümünü Kamu SM'ye senkron tutmaz; elle çalıştırıp
# PR ile snapshot'ı güncellersiniz. Offline trust bootstrap için (chain.ts).

set -euo pipefail
cd "$(dirname "$0")/.."

URL="${URL:-http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml}"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

echo "Fetching $URL …"
curl -fsSL "$URL" > "$TMP/depo.xml"

# XML'de Kök CA cert'leri yakala (<Sertifika>…<Deger>base64</Deger>).
# Sadece kök olanlar (Issuer==Subject) filtre edilir.
python3 - "$TMP/depo.xml" "$TMP/roots" <<'PY'
import sys, re, base64, os, subprocess
xml = open(sys.argv[1], 'rb').read().decode('utf-8', errors='replace')
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)

# Kamu SM şeması: <koksertifika><mValue>base64</mValue>...<mSubjectName>b64DN</mSubjectName>
#                                    <mIssuerName>b64DN</mIssuerName>...</koksertifika>
block_rx = re.compile(r'<koksertifika>(.*?)</koksertifika>', re.DOTALL)
val_rx = re.compile(r'<mValue>\s*([A-Za-z0-9+/=\s]+?)\s*</mValue>')
subj_rx = re.compile(r'<mSubjectName>\s*([A-Za-z0-9+/=\s]+?)\s*</mSubjectName>')
issr_rx = re.compile(r'<mIssuerName>\s*([A-Za-z0-9+/=\s]+?)\s*</mIssuerName>')

seen = set()
count = 0
for idx, block in enumerate(block_rx.findall(xml)):
    v = val_rx.search(block)
    s = subj_rx.search(block)
    i = issr_rx.search(block)
    if not (v and s and i):
        continue
    b64 = ''.join(v.group(1).split())
    subj_b64 = ''.join(s.group(1).split())
    issr_b64 = ''.join(i.group(1).split())
    # Root = subject == issuer (self-signed).
    if subj_b64 != issr_b64:
        continue
    if subj_b64 in seen:
        continue
    try:
        der = base64.b64decode(b64)
    except Exception:
        continue
    seen.add(subj_b64)
    pem_body = '\n'.join(b64[j:j+64] for j in range(0, len(b64), 64))
    pem = f'-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----\n'
    with open(os.path.join(outdir, f'root-{count:02d}.pem'), 'w') as f:
        f.write(pem)
    count += 1
print(f'{count} root cert(s) extracted')
PY

shopt -s nullglob
COUNT=$(ls "$TMP/roots/"*.pem 2>/dev/null | wc -l | tr -d ' ')
echo "Extracted $COUNT root cert(s)"

# src/kamusm-roots-snapshot.ts üret
OUT="src/kamusm-roots-snapshot.ts"
{
  echo "// Auto-generated — bash reference/fetch-kamusm-roots.sh çıktısı."
  echo "// Kamu SM Sertifika Deposu'ndan (http://depo.kamusm.gov.tr) çıkarılan"
  echo "// root CA sertifikaları (subject == issuer)."
  echo "// Manuel refresh — bu dosyayı doğrudan edit ETMEYİN, script'i çalıştırın."
  echo "// Snapshot tarihi: $(date +%Y-%m-%d)"
  echo ""
  echo "export const KAMUSM_ROOTS_PEM: readonly string[] = ["
  for pem in "$TMP/roots/"*.pem; do
    body=$(cat "$pem")
    echo "  \`$body\`,"
  done
  echo "];"
  echo ""
  echo "/** PEM → DER (Uint8Array). chain.ts içinde roots[] olarak kullanılır. */"
  echo "export function kamuSmRootsDer(): Uint8Array[] {"
  echo "  return KAMUSM_ROOTS_PEM.map((pem) => pemToDer(pem));"
  echo "}"
  echo ""
  echo "function pemToDer(pem: string): Uint8Array {"
  echo "  const b64 = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\\s+/g, \"\");"
  echo "  return new Uint8Array(Buffer.from(b64, \"base64\"));"
  echo "}"
} > "$OUT"

echo "Wrote $OUT with $COUNT root cert(s)"
