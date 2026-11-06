#!/usr/bin/env python3
"""Зводить результати osv-scanner і trivy, порівнює з попереднім запуском
і надсилає в Telegram лише НОВЕ (плюс коротко — що закрито).

Змінні середовища:
  OUT_DIR            каталог з результатами scan.sh (.secscan-out)
  STATE_FILE         файл стану з попереднього запуску (JSON); якщо його немає — це перший запуск
  MIN_SEVERITY       LOW | MEDIUM | HIGH | CRITICAL (за замовчуванням MEDIUM)
  ONLY_FIXABLE       true/false — повідомляти лише про те, для чого є виправлення (за замовчуванням false)
  NOTIFY             true/false — чи надсилати в Telegram
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  REPO, RUN_URL      для заголовка повідомлення
  FAIL_ON            none | HIGH | CRITICAL — завершити з кодом 1, якщо є НОВІ знахідки цього рівня
"""
import html
import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

SEV_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "⬜", "UNKNOWN": "⬜"}

OUT = pathlib.Path(os.environ.get("OUT_DIR", ".secscan-out"))
STATE_FILE = pathlib.Path(os.environ.get("STATE_FILE", ".secscan-state/state.json"))
MIN_SEV = os.environ.get("MIN_SEVERITY", "MEDIUM").upper()
ONLY_FIXABLE = os.environ.get("ONLY_FIXABLE", "false").lower() == "true"
NOTIFY = os.environ.get("NOTIFY", "true").lower() == "true"
REPO = os.environ.get("REPO", "local")
RUN_URL = os.environ.get("RUN_URL", "")
FAIL_ON = os.environ.get("FAIL_ON", "none").upper()


def cvss_to_sev(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0:
        return "LOW"
    return "UNKNOWN"


def osv_findings():
    p = OUT / "osv.json"
    if not p.exists():
        return []
    data = json.loads(p.read_text() or "{}")
    res = []
    for r in data.get("results") or []:
        src = os.path.relpath(r.get("source", {}).get("path", "?"), os.getcwd())
        for pk in r.get("packages") or []:
            pkg = pk.get("package", {})
            vulns = {v["id"]: v for v in pk.get("vulnerabilities") or []}
            for g in pk.get("groups") or []:
                ids = g.get("ids") or []
                aliases = g.get("aliases") or ids
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                main_id = cve or next((a for a in aliases if a.startswith("GHSA-")), ids[0] if ids else "?")
                fixed, summary = set(), ""
                for i in ids:
                    v = vulns.get(i, {})
                    summary = summary or v.get("summary") or ""
                    for a in v.get("affected") or []:
                        if a.get("package", {}).get("name", "").lower() not in ("", pkg.get("name", "").lower()):
                            continue
                        for rg in a.get("ranges") or []:
                            if rg.get("type") == "GIT":
                                continue
                            for e in rg.get("events") or []:
                                if "fixed" in e:
                                    fixed.add(e["fixed"])
                res.append({
                    "key": f"osv|{src}|{pkg.get('ecosystem')}|{pkg.get('name')}|{pkg.get('version')}|{main_id}",
                    "kind": "dep",
                    "where": src,
                    "pkg": f"{pkg.get('name')} {pkg.get('version')} ({pkg.get('ecosystem')})",
                    "id": main_id,
                    "sev": cvss_to_sev(g.get("max_severity")),
                    "fixed": ", ".join(sorted(fixed)[:3]),
                    "title": summary[:120],
                })
    return res


def trivy_findings():
    res, eol = [], []
    for p in sorted((OUT / "trivy").glob("img-*.json")):
        d = json.loads(p.read_text() or "{}")
        label = d.get("_label", d.get("ArtifactName", "?"))
        os_md = (d.get("Metadata") or {}).get("OS") or {}
        if os_md.get("EOSL"):
            eol.append({
                "key": f"eol|{label}|{os_md.get('Family')}|{os_md.get('Name')}",
                "kind": "eol", "where": label, "id": "EOL",
                "pkg": f"{os_md.get('Family')} {os_md.get('Name')}", "sev": "HIGH",
                "fixed": "перейти на підтримувану гілку", "title": "Гілка ОС більше не отримує оновлень безпеки",
            })
        for r in d.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                res.append({
                    "key": f"trivy|{label}|{v.get('PkgName')}|{v.get('InstalledVersion')}|{v.get('VulnerabilityID')}",
                    "kind": "image", "where": label,
                    "pkg": f"{v.get('PkgName')} {v.get('InstalledVersion')}",
                    "id": v.get("VulnerabilityID"), "sev": (v.get("Severity") or "UNKNOWN").upper(),
                    "fixed": v.get("FixedVersion") or "", "title": (v.get("Title") or "")[:120],
                })
    p = OUT / "trivy-config.json"
    if p.exists():
        d = json.loads(p.read_text() or "{}")
        for r in d.get("Results") or []:
            for m in r.get("Misconfigurations") or []:
                if m.get("Status") != "FAIL":
                    continue
                res.append({
                    "key": f"cfg|{r.get('Target')}|{m.get('ID')}",
                    "kind": "config", "where": r.get("Target"), "pkg": "Dockerfile",
                    "id": m.get("ID"), "sev": (m.get("Severity") or "UNKNOWN").upper(),
                    "fixed": (m.get("Resolution") or "")[:100], "title": (m.get("Title") or "")[:120],
                })
    return res + eol


def keep(f):
    if SEV_ORDER.get(f["sev"], 0) < SEV_ORDER.get(MIN_SEV, 2):
        return False
    if ONLY_FIXABLE and f["kind"] in ("dep", "image") and not f["fixed"]:
        return False
    return True


def fmt(f):
    e = html.escape
    fix = f"→ <b>{e(f['fixed'])}</b>" if f["fixed"] else "→ <i>виправлення немає</i>"
    return f"{SEV_ICON.get(f['sev'], '⬜')} <code>{e(f['id'])}</code> {e(f['pkg'])} {fix}\n    <i>{e(f['where'])}</i>"


def vkey(v):
    out = []
    for part in v.replace("-", ".").split("."):
        out.append((0, int(part)) if part.isdigit() else (1, part))
    return out


def grouped(items):
    """Групує знахідки за (де, пакет): один рядок на пакет з кількістю CVE і найвищою версією-фіксом."""
    groups = {}
    for f in items:
        groups.setdefault((f["where"], f["pkg"], f["kind"]), []).append(f)
    lines = []
    e = html.escape
    for (where, pkg, kind), fs in sorted(groups.items(), key=lambda kv: -max(SEV_ORDER.get(x["sev"], 0) for x in kv[1])):
        top = max(fs, key=lambda x: SEV_ORDER.get(x["sev"], 0))
        if len(fs) == 1:
            lines.append(fmt(top))
            continue
        fixes = [x["fixed"].split(",")[-1].strip() for x in fs if x["fixed"]]
        fix = f"→ <b>≥ {e(max(fixes, key=vkey))}</b>" if fixes and kind in ("dep", "image") else ""
        ids = ", ".join(e(x["id"]) for x in sorted(fs, key=lambda x: -SEV_ORDER.get(x["sev"], 0))[:4])
        more = f" +{len(fs) - 4}" if len(fs) > 4 else ""
        lines.append(f"{SEV_ICON.get(top['sev'], '⬜')} {e(pkg)} — {len(fs)} шт. {fix}\n    <code>{ids}</code>{more}\n    <i>{e(where)}</i>")
    return lines


def send(text):
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (token and chat):
        print("::warning::TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID не задані — повідомлення не надіслано")
        return
    # Telegram обмежує повідомлення 4096 символами — ділимо по рядках
    chunks, cur = [], ""
    for line in text.split("\n"):
        if len(cur) + len(line) + 1 > 3900:
            chunks.append(cur)
            cur = ""
        cur += line + "\n"
    chunks.append(cur)
    for c in chunks:
        body = urllib.parse.urlencode({"chat_id": chat, "text": c, "parse_mode": "HTML",
                                       "disable_web_page_preview": "true"}).encode()
        try:
            urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", body, timeout=30).read()
        except Exception as ex:  # не валимо job через Telegram
            print(f"::warning::Telegram: {ex}")


def main():
    findings = [f for f in osv_findings() + trivy_findings() if keep(f)]
    current = {f["key"]: f for f in findings}
    first_run = not STATE_FILE.exists()
    prev = {} if first_run else json.loads(STATE_FILE.read_text() or "{}")
    prev_errors = set(prev.pop("_errors", []))
    new = [f for k, f in current.items() if k not in prev]
    resolved = [f for k, f in prev.items() if k not in current]
    new.sort(key=lambda f: -SEV_ORDER.get(f["sev"], 0))

    errors = (OUT / "errors.txt").read_text().strip().splitlines() if (OUT / "errors.txt").exists() else []

    # підсумок у GitHub (вкладка Summary запуску) — завжди
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as s:
            s.write(f"## Security scan: {len(current)} знахідок (нових: {len(new)}, закрито: {len(resolved)})\n\n")
            if current:
                s.write("| Рівень | ID | Пакет | Виправлення | Де |\n|---|---|---|---|---|\n")
                for f in sorted(current.values(), key=lambda f: -SEV_ORDER.get(f["sev"], 0)):
                    s.write(f"| {f['sev']} | {f['id']} | {f['pkg']} | {f['fixed'] or '—'} | {f['where']} |\n")
            if errors:
                s.write("\n**Помилки сканування:** " + "; ".join(errors) + "\n")

    # Telegram — лише якщо є що сказати
    new_errors = [x for x in errors if x not in prev_errors]
    if NOTIFY and (new or resolved or new_errors):
        e = html.escape
        head = "🛡 <b>{}</b>".format(e(REPO))
        if first_run:
            head += f" — перше сканування: {len(current)} знахідок"
        else:
            head += f" — нових: {len(new)}, закрито: {len(resolved)}"
        lines = [head]
        by_sev = {}
        for f in current.values():
            by_sev[f["sev"]] = by_sev.get(f["sev"], 0) + 1
        if by_sev:
            lines.append(" · ".join(f"{SEV_ICON[s]} {s}: {by_sev[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in by_sev))
        if new:
            lines.append("")
            lines.append("<b>Нове:</b>" if not first_run else "<b>Знахідки:</b>")
            g = grouped(new)
            lines += g[:30]
            if len(g) > 30:
                lines.append(f"… і ще {len(g) - 30} пакетів — дивіться звіт запуску")
        if resolved:
            lines.append("")
            lines.append("✅ <b>Закрито:</b> " + ", ".join(e(f["id"]) for f in resolved[:20])
                         + (f" … (+{len(resolved) - 20})" if len(resolved) > 20 else ""))
        if new_errors:
            lines.append("")
            lines.append("⚠️ <b>Попередження:</b>")
            lines += ["• " + e(x[:200]) for x in new_errors[:10]]
        if RUN_URL:
            lines.append("")
            lines.append(f'<a href="{e(RUN_URL)}">Звіт запуску</a>')
        send("\n".join(lines))

    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({**current, "_errors": errors}, ensure_ascii=False))
    print(f"знахідок: {len(current)}, нових: {len(new)}, закрито: {len(resolved)}, помилок: {len(errors)}")

    if FAIL_ON in SEV_ORDER and any(SEV_ORDER.get(f["sev"], 0) >= SEV_ORDER[FAIL_ON] for f in new):
        sys.exit(1)


if __name__ == "__main__":
    main()
