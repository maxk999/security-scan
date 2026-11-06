#!/usr/bin/env bash
# Встановлює безпековий моніторинг у поточний проєкт:
#   .github/workflows/security.yml  — щоденне сканування (викликає maxk999/security-scan)
#   .github/dependabot.yml          — автоматичні PR з виправленнями (генерується під стек проєкту)
# Нічого не комітить і не пушить — лише створює файли.
#
# Використання (у корені проєкту):
#   bash install.sh                 # створити файли
#   bash install.sh --secrets       # + записати секрети Telegram і ввімкнути Dependabot через gh
#   bash install.sh --force         # перезаписати наявні файли
set -euo pipefail

FORCE=false; SECRETS=false
for a in "$@"; do
  case "$a" in
    --force) FORCE=true;; --secrets) SECRETS=true;;
    *) echo "невідомий параметр: $a"; exit 2;;
  esac
done

[ -d .git ] || { echo "Запускайте в корені git-репозиторію"; exit 1; }
mkdir -p .github/workflows

write() {  # $1 = шлях; вміст зі stdin
  if [[ -e "$1" && "$FORCE" != true ]]; then
    echo "• $1 вже існує — пропускаю (додайте --force, щоб перезаписати)"; cat >/dev/null; return
  fi
  cat > "$1"; echo "✓ $1"
}

# ---------- 1. workflow
# хвилина й година зсунуті від :00, щоб не потрапляти в чергу GitHub
MIN=$(( $(printf '%s' "$PWD" | cksum | cut -d' ' -f1) % 50 + 5 ))
write .github/workflows/security.yml <<EOF
name: security

on:
  schedule:
    - cron: "${MIN} 6 * * *"     # щодня (~09:${MIN} за Києвом взимку)
  push:
    branches: [main, master]
    paths:
      - "**/requirements*.txt"
      - "**/pyproject.toml"
      - "**/poetry.lock"
      - "**/uv.lock"
      - "**/Pipfile.lock"
      - "**/package.json"
      - "**/package-lock.json"
      - "**/yarn.lock"
      - "**/pnpm-lock.yaml"
      - "**/*.csproj"
      - "**/packages.lock.json"
      - "**/packages.config"
      - "**/Dockerfile*"
      - "**/*compose*.y*ml"
      - ".github/workflows/**"
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    uses: maxk999/security-scan/.github/workflows/scan.yml@main
    with:
      min-severity: MEDIUM
      only-fixable: false
      build-images: true
      fail-on: none
    secrets:
      TELEGRAM_BOT_TOKEN: \${{ secrets.TELEGRAM_BOT_TOKEN }}
      TELEGRAM_CHAT_ID: \${{ secrets.TELEGRAM_CHAT_ID }}
EOF

# ---------- 2. dependabot.yml під фактичний стек
dirs_of() {  # каталоги (відносно кореня, з "/") для файлів за шаблонами find
  find . \( -path ./.git -o -path '*/node_modules' -o -path '*/.venv' -o -path '*/venv' \) -prune -o -type f \( "$@" \) -exec dirname {} + \
    | sed -E 's#^\.##; s#^$#/#' | sort -u
}
yaml_dirs() { while IFS= read -r d; do echo "      - \"$d\""; done; }

PY_DIRS=$(dirs_of -name 'requirements*.txt' -o -name pyproject.toml -o -name Pipfile -o -name setup.py)
UV_DIRS=$(dirs_of -name uv.lock)
NPM_DIRS=$(dirs_of -name package.json)
NUGET_DIRS=$(dirs_of -name '*.csproj' -o -name '*.fsproj' -o -name packages.config -o -name '*.sln')
DOCKER_DIRS=$(dirs_of -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.Dockerfile' -o -name Containerfile)
COMPOSE_DIRS=$(dirs_of -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml')

{
  echo "# Згенеровано install.sh із security-scan. Перегенерувати: bash install.sh --force"
  echo "version: 2"
  echo "updates:"
  # Бібліотеки: лише БЕЗПЕКОВІ оновлення (limit 0 вимикає звичайні version updates,
  # security updates Dependabot відкриває незалежно — їх треба ввімкнути в налаштуваннях репозиторію).
  lib_block() {  # $1 = ecosystem, $2 = каталоги
    [ -z "$2" ] && return
    cat <<EOB
  - package-ecosystem: "$1"
    directories:
$(echo "$2" | yaml_dirs)
    schedule:
      interval: "daily"
    open-pull-requests-limit: 0
    labels: ["security", "dependencies"]
    commit-message:
      prefix: "security"
EOB
  }
  # Docker/Actions: у Dependabot немає бази вразливостей для образів, тому вмикаємо оновлення тегів,
  # але без мажорних стрибків (python:3.12-alpine3.20 -> новіший патч/мінор, не 4.x).
  tag_block() {  # $1 = ecosystem, $2 = каталоги
    [ -z "$2" ] && return
    cat <<EOB
  - package-ecosystem: "$1"
    directories:
$(echo "$2" | yaml_dirs)
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    labels: ["security", "docker"]
    commit-message:
      prefix: "security"
    ignore:
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]
    groups:
      $1-base-images:
        patterns: ["*"]
EOB
  }
  if [ -n "$UV_DIRS" ]; then lib_block uv "$UV_DIRS"; fi
  lib_block pip "$(comm -23 <(echo "$PY_DIRS" | sed '/^$/d') <(echo "$UV_DIRS" | sed '/^$/d'))"
  lib_block npm "$NPM_DIRS"
  lib_block nuget "$NUGET_DIRS"
  tag_block docker "$DOCKER_DIRS"
  tag_block docker-compose "$COMPOSE_DIRS"
  cat <<EOB
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    labels: ["security", "ci"]
    commit-message:
      prefix: "security"
    groups:
      actions:
        patterns: ["*"]
EOB
} | write .github/dependabot.yml

echo
echo "Знайдений стек:"
[ -n "$PY_DIRS$UV_DIRS" ] && echo "  Python:  $(echo $PY_DIRS $UV_DIRS | tr '\n' ' ')"
[ -n "$NPM_DIRS" ]        && echo "  Node:    $(echo $NPM_DIRS | tr '\n' ' ')"
[ -n "$NUGET_DIRS" ]      && echo "  .NET:    $(echo $NUGET_DIRS | tr '\n' ' ')"
[ -n "$DOCKER_DIRS" ]     && echo "  Docker:  $(echo $DOCKER_DIRS | tr '\n' ' ')"
[ -n "$COMPOSE_DIRS" ]    && echo "  Compose: $(echo $COMPOSE_DIRS | tr '\n' ' ')"
grep -rlsE '^\s*FROM\s+\S*alpine' --include='Dockerfile*' --include='*.Dockerfile' . 2>/dev/null | sed 's/^/  Alpine:  /' || true

# ---------- 3. секрети та налаштування репозиторію (опційно, потрібен gh)
if [[ "$SECRETS" == true ]]; then
  command -v gh >/dev/null || { echo "gh не встановлено — секрети задайте вручну"; exit 0; }
  REPO_SLUG=$(gh repo view --json nameWithOwner -q .nameWithOwner)
  [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] || read -rsp "TELEGRAM_BOT_TOKEN: " TELEGRAM_BOT_TOKEN; echo
  [[ -n "${TELEGRAM_CHAT_ID:-}"  ]] || read -rp  "TELEGRAM_CHAT_ID: "   TELEGRAM_CHAT_ID
  printf '%s' "$TELEGRAM_BOT_TOKEN" | gh secret set TELEGRAM_BOT_TOKEN -R "$REPO_SLUG"
  printf '%s' "$TELEGRAM_CHAT_ID"  | gh secret set TELEGRAM_CHAT_ID  -R "$REPO_SLUG"
  # Dependabot alerts + security updates (автоматичні PR з виправленнями)
  gh api -X PUT "repos/$REPO_SLUG/vulnerability-alerts"     >/dev/null && echo "✓ Dependabot alerts"
  gh api -X PUT "repos/$REPO_SLUG/automated-security-fixes" >/dev/null && echo "✓ Dependabot security updates"
fi

echo
echo "Далі: git add .github && git commit -m 'security: моніторинг вразливостей' && git push (через гілку/PR)."
