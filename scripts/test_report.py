# security-scan: перевірка вибору версії-фіксу (report.pick_fix)
# Створено: 2026-11-14; оновлено: 2026-11-14
# Запуск: python3 -I scripts/test_report.py
import importlib.util
import pathlib

spec = importlib.util.spec_from_file_location("report", pathlib.Path(__file__).with_name("report.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

assert r.pick_fix({"6.4.4", "7.3.7", "8.1.6", "8.2.4", "8.3.3"}, "8.2.1") == "8.2.4"
assert r.pick_fix({"1.1.19", "2.1.5", "3.0.7", "5.0.10"}, "5.0.9") == "5.0.10"
assert r.pick_fix({"1.1.19", "2.1.5", "3.0.7"}, "5.0.9") == "1.1.19, 2.1.5, 3.0.7"  # у гілці фіксу немає
assert r.pick_fix({"1.24.13", "1.24.9", "1.25.7"}, "1.24.6") == "1.24.9"  # числами, не рядками
assert r.pick_fix({"2.8.0"}, "") == "2.8.0"
print("ok")

# digest образу не робить ті самі CVE «новими» + «закритими»
assert r.norm("./docker-compose.yml: image postgres:18.7-trixie@sha256:9f4fd4aa") == "./docker-compose.yml: image postgres:18.7-trixie"

# повідомлення: пункти дій за файлами, без CVE-кодів, без власника репо
img = "./docker-compose.yml: image postgres:18.7-trixie"
cur = [{"key": f"k{i}", "kind": "image", "where": img, "pkg": "stdlib v1.24.6", "id": f"CVE-{i}",
        "sev": "CRITICAL" if i == 0 else "HIGH", "fixed": "1.27.3" if i < 3 else "", "title": ""} for i in range(5)]
cur.append({"key": "d1", "kind": "dep", "where": "web/package-lock.json", "pkg": "vite 8.2.1 (npm)", "id": "GHSA-x",
            "sev": "MEDIUM", "fixed": "8.2.4", "title": ""})
r.REPO = "MaxKramR/ShelfViewer"
t = r.telegram_text(cur, [cur[-1]], [], [], False)
print(t)
assert "ShelfViewer</b> — 🔴 потрібна дія" in t and "MaxKramR" not in t and "CVE-" not in t
assert t.index("docker-compose.yml") < t.index("web/package-lock.json")  # критичне першим
assert "vite → <b>8.2.4</b>" in t and "🆕" in t and "Ще 2 без виправлення" in t
print("ok")
