#!/usr/bin/env bash
# Сканує поточний репозиторій: залежності (osv-scanner) + Docker-образи (trivy).
# Результати складає в $OUT_DIR (за замовчуванням ./.secscan-out).
# Скрипт навмисно "м'який": помилка одного сканера не зупиняє інші.
set -uo pipefail

OUT_DIR="${OUT_DIR:-.secscan-out}"
OSV="${OSV_BIN:-osv-scanner}"
TRIVY="${TRIVY_BIN:-trivy}"
BUILD_IMAGES="${BUILD_IMAGES:-true}"     # пробувати docker build для кожного Dockerfile
BUILD_TIMEOUT="${BUILD_TIMEOUT:-900}"    # секунд на одну збірку
EXCLUDES=(-path ./.git -o -path '*/node_modules' -o -path '*/.venv' -o -path '*/venv' -o -path "./$OUT_DIR")

rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR/trivy"
: > "$OUT_DIR/log.txt"
log() { echo "[secscan] $*" | tee -a "$OUT_DIR/log.txt" >&2; }

# ---------- 1. Залежності: osv-scanner (pip, poetry, uv, npm, yarn, pnpm, NuGet, go, cargo, composer, GitHub Actions …)
log "osv-scanner: сканую маніфести й lock-файли"
"$OSV" scan source -r --format json --output-file "$OUT_DIR/osv.json" \
  --x-exclude node_modules --x-exclude .venv --x-exclude venv . >>"$OUT_DIR/log.txt" 2>&1
rc=$?
# 0 = нічого не знайдено, 1 = знайдено вразливості, 128 = не знайдено жодного маніфесту
case $rc in
  0|1) log "osv-scanner: готово (rc=$rc)";;
  128) log "osv-scanner: маніфестів не знайдено"; echo '{"results":[]}' > "$OUT_DIR/osv.json";;
  *)   log "osv-scanner: ПОМИЛКА rc=$rc"; echo "osv-scanner rc=$rc" >> "$OUT_DIR/errors.txt"
       [ -s "$OUT_DIR/osv.json" ] || echo '{"results":[]}' > "$OUT_DIR/osv.json";;
esac

# package.json без lock-файла osv-scanner не перевіряє — попереджаємо
while IFS= read -r pj; do
  d="$(dirname "$pj")"
  found=false
  for lf in package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock; do [ -e "$d/$lf" ] && found=true; done
  $found || { log "немає lock-файла в $d"; echo "$pj: немає lock-файла (npm install --package-lock-only) — залежності не перевірені" >> "$OUT_DIR/errors.txt"; }
done < <(find . \( "${EXCLUDES[@]}" \) -prune -o -type f -name package.json -print)

# ---------- 2. Docker: Dockerfile-и та образи з docker-compose
mapfile -t DOCKERFILES < <(find . \( "${EXCLUDES[@]}" \) -prune -o -type f \( -name Dockerfile -o -name 'Dockerfile.*' -o -name '*.Dockerfile' -o -name 'Containerfile' \) -print | sort)
mapfile -t COMPOSE < <(find . \( "${EXCLUDES[@]}" \) -prune -o -type f \( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' \) -print | sort)

declare -A SCANNED=()
n=0
scan_image() {   # $1 = образ, $2 = мітка для звіту
  local img="$1" label="$2" f
  [[ -n "${SCANNED[$img]:-}" ]] && return 0
  SCANNED[$img]=1
  n=$((n+1)); f="$OUT_DIR/trivy/img-$n.json"
  log "trivy: образ $img ($label)"
  if "$TRIVY" image --quiet --format json --scanners vuln --output "$f" "$img" >>"$OUT_DIR/log.txt" 2>&1; then
    python3 -I - "$f" "$label" <<'PY'
import json,sys
p,label=sys.argv[1],sys.argv[2]
d=json.load(open(p)); d["_label"]=label; json.dump(d,open(p,"w"))
PY
  else
    log "trivy: не вдалося просканувати $img"; echo "trivy image $img ($label)" >> "$OUT_DIR/errors.txt"; rm -f "$f"
  fi
}

# Базові образи з Dockerfile (FROM), без змінних і без посилань на попередні стадії
base_images() {
  python3 -I - "$1" <<'PY'
import re,sys
stages=set(); out=[]
for line in open(sys.argv[1],encoding="utf-8",errors="ignore"):
    m=re.match(r'\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?',line,re.I)
    if not m: continue
    img,alias=m.group(1),m.group(2)
    if "$" not in img and img.lower()!="scratch" and img.lower() not in stages: out.append(img)
    if alias: stages.add(alias.lower())
print("\n".join(dict.fromkeys(out)))
PY
}

for df in "${DOCKERFILES[@]}"; do
  ctx="$(dirname "$df")"
  if [[ "$BUILD_IMAGES" == "true" ]] && command -v docker >/dev/null; then
    tag="secscan-local-$(echo "$df" | md5sum | cut -c1-8):latest"
    log "docker build $df"
    if timeout "$BUILD_TIMEOUT" docker build -q -f "$df" -t "$tag" "$ctx" >>"$OUT_DIR/log.txt" 2>&1; then
      scan_image "$tag" "$df (зібраний образ)"
    else
      log "docker build не вдався для $df — сканую лише базові образи"
    fi
  fi
  # базові образи скануємо завжди: так видно EOL-гілку Alpine і що дасть оновлення тегу
  while IFS= read -r img; do [[ -n "$img" ]] && scan_image "$img" "$df: FROM $img"; done < <(base_images "$df")
done

for cf in "${COMPOSE[@]}"; do
  while IFS= read -r img; do
    [[ -n "$img" && "$img" != *'$'* ]] && scan_image "$img" "$cf: image $img"
  done < <(grep -E '^\s*image:\s*' "$cf" | sed -E 's/^\s*image:\s*["'\'']?([^"'\'' #]+).*/\1/')
done

# ---------- 3. Помилки конфігурації Dockerfile (лише HIGH/CRITICAL, щоб не шуміти)
if [[ ${#DOCKERFILES[@]} -gt 0 ]]; then
  log "trivy config: перевіряю Dockerfile-и"
  "$TRIVY" config --quiet --format json --severity HIGH,CRITICAL --output "$OUT_DIR/trivy-config.json" . >>"$OUT_DIR/log.txt" 2>&1 \
    || echo "trivy config" >> "$OUT_DIR/errors.txt"
fi

log "готово: Dockerfile=${#DOCKERFILES[@]}, compose=${#COMPOSE[@]}, образів проскановано=$n"
exit 0
