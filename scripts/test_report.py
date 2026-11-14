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
