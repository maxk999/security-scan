# security-scan

Безпековий моніторинг, який ставиться в будь-який проєкт двома файлами. Він сам розпізнає стек проєкту, щодня перевіряє вразливості, відкриває PR з виправленнями й пише в Telegram, коли знаходить щось нове.

## Що перевіряється

| Що | Чим | Що знаходить |
|---|---|---|
| Python, Node, .NET, Go, PHP, Rust… (lock-файли та маніфести) | osv-scanner (база OSV / GitHub Advisory) | CVE у залежностях і версію, де їх виправлено |
| Dockerfile | `docker build`, потім `trivy image` | вразливі пакети образу, зокрема з `apk add` (openssl, musl, busybox, curl…) |
| `FROM` у Dockerfile та `image:` у docker-compose | `trivy image` | вразливості базового образу, **EOL-гілку Alpine** |
| Dockerfile (конфігурація) | `trivy config` (лише HIGH/CRITICAL) | наприклад, запуск від root, секрети в образі |
| Виправлення | Dependabot | PR з мінімальною безпечною версією бібліотеки; PR з новішим тегом образу без мажорних стрибків |

**Telegram** отримує повідомлення лише тоді, коли з'явилася нова знахідка, щось закрилося або виникла нова помилка сканування. Повний список знахідок завжди є у звіті запуску (Actions → запуск → Summary) і в артефакті `secscan-results`.

## Встановлення

### 1. Один раз: центральний репозиторій
1. Створіть репозиторій `maxk999/security-scan`, **публічний**. Секретів у ньому немає. Публічним він має бути, щоб його workflow могли викликати й репозиторії `MaxKramR`: приватні reusable workflows доступні лише в межах одного акаунта.
2. Залийте в нього вміст цієї теки.

### 2. Один раз: Telegram-бот
1. У @BotFather виконайте `/newbot` і отримайте **токен**.
2. Напишіть боту будь-що (або додайте його в групу), потім відкрийте `https://api.telegram.org/bot<ТОКЕН>/getUpdates` і візьміть `chat.id`. Для груп він від'ємний.

### 3. У кожен проєкт
```bash
cd <проєкт>
git switch -c security/monitoring
curl -fsSL https://raw.githubusercontent.com/maxk999/security-scan/main/install/install.sh -o /tmp/secscan-install.sh
bash /tmp/secscan-install.sh --secrets   # згенерує файли, запише секрети й увімкне Dependabot (потрібен gh)
git add .github && git commit -m "security: моніторинг вразливостей" && git push -u origin HEAD
```
Далі відкрийте PR і змерджіть його. Без `gh` запускайте без `--secrets` і задайте вручну:
- Settings → Secrets and variables → Actions: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, за потреби `TELEGRAM_THREAD_ID` (id гілки в групі-форумі: число після останнього `/` у посиланні на повідомлення гілки);
- Settings → Code security: **Dependabot alerts** і **Dependabot security updates** → Enable.

Після мерджу запустіть перевірку вручну: Actions → security → Run workflow. Перше повідомлення міститиме всі поточні знахідки, а далі приходитимуть лише зміни.

## Налаштування (у `.github/workflows/security.yml` проєкту)
| Параметр | За замовчуванням | |
|---|---|---|
| `min-severity` | `MEDIUM` | нижчі рівні не потрапляють у звіт |
| `only-fixable` | `false` | `true` — показувати лише те, для чого вже є виправлення |
| `build-images` | `true` | `false` — не збирати образи, сканувати тільки базові |
| `fail-on` | `none` | `HIGH`/`CRITICAL` — валити перевірку в PR, якщо PR приносить нову вразливість |

Розклад задається рядком `cron` у тому ж файлі. Час там у UTC.

## Обмеження
- **npm без `package-lock.json`** не перевіряється. Скрипт попередить про це в Telegram. Виправлення: `npm install --package-lock-only` і закомітити lock-файл.
- **`requirements.txt` без фіксованих версій** (`requests>=2`) перевіряється неточно, бо невідомо, яка версія насправді ставиться. Краще фіксувати версії (`==`) або тримати lock-файл (poetry/uv).
- **1C** автоматично не сканується: для платформи 1C немає публічної бази вразливостей.
- Якщо `docker build` потребує секретів або build-args, збірка не пройде. Тоді скануються лише базові образи, без пакетів з `apk add`.
- Dependabot не має бази вразливостей для Docker-образів. Тому для образів він просто пропонує новіші теги раз на тиждень, а вразливості в них ловить trivy.
- GitHub Actions для приватних репозиторіїв має безкоштовний ліміт 2000 хв/міс. Одне сканування триває приблизно 2–6 хв.
