import json
from pathlib import Path
from datetime import datetime, timezone

analysis_id = "9075d43b-19d1-45b3-8525-d78e5fd71b2c"

folders = [
    p.parent for p in Path("runs").glob("*/manifest.json")
    if json.loads(p.read_text()).get("analysis_id") == analysis_id
]
if len(folders) != 1:
    raise SystemExit("Không xác định được duy nhất thư mục lượt chạy.")

folder = folders[0]
rows = json.loads((folder / "ai_results.json").read_text())

selected = []
for name, line in (("Trial04.java", 20), ("VulnerableLogin.java", 15)):
    matches = [
        r for r in rows
        if r.get("component", "").endswith("/" + name)
        and r.get("line") == line
        and r.get("processing_status") == "AI_PROPOSED"
    ]
    if len(matches) != 1:
        raise SystemExit(f"{name}: không xác định được đúng cảnh báo.")
    selected.append(matches[0])

choices = {
    "TP": "LIKELY_TP",
    "FP": "LIKELY_FP",
    "UNKNOWN": "UNKNOWN",
}

for row in selected:
    print("\nFILE:", row["component"])
    print("AI ĐỀ XUẤT:", row["ai_verdict"])
    label = input("Kết luận sau đối chiếu code [TP/FP/UNKNOWN]: ").strip().upper()
    if label not in choices:
        raise SystemExit("Nhãn không hợp lệ; chưa ghi file.")

    notes = input("Lý do và dòng code làm bằng chứng: ").strip()
    if not notes:
        raise SystemExit("Cần ghi bằng chứng; chưa ghi file.")

    verdict = choices[label]
    row["reviewed_verdict"] = verdict
    row["review_status"] = (
        "CONFIRMED" if verdict == row["ai_verdict"] else "CORRECTED"
    )
    row["review_notes"] = notes
    row["review_method"] = "user_entered_in_terminal"
    row["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    row["requires_review"] = False

stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
output = folder / f"reviewed_results_{stamp}.json"
with output.open("x", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False, indent=2)

for row in selected:
    print(
        row["component"].split("/")[-1],
        "| AI:", row["ai_verdict"],
        "| Sau thẩm định:", row["reviewed_verdict"],
    )
print("ĐÃ LƯU:", output)
print("ai_results.json gốc được giữ nguyên.")

