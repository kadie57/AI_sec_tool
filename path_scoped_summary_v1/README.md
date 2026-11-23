# Path scoped explanation v1

Chép path_triage_v2.py và replay_path_explanation.py vào ~/AI_sec_tool sau khi sao lưu file cùng tên. source_audit_v2.py giữ nguyên bản trước, không cần chép lại.

Mục tiêu: trình bày facts AI với phạm vi rõ ràng, lưu explanation_original, source_explanation_original, path_explanation_original và explanation_limitations. Giữ nguyên toàn bộ lời giải thích gốc trong phần có nhãn cảnh báo để UI hiện có không làm mất thông tin. Không sửa lời AI gốc bằng thay chuỗi, không gán đáp án theo tên mẫu.

Không thay prompt, mô hình, schema, policy quyết định hoặc yêu cầu thẩm định. prompt_version vẫn là v4 vì request AI không đổi; explanation_version mới là path-scoped-summary-v1. Hash script thay đổi nên lượt chạy pipeline mới tách khỏi checkpoint cũ.

Đây KHÔNG phải sửa ngữ nghĩa AI hoặc chứng minh CONFINED. Các khẳng định quá mức trong giải thích gốc vẫn là hạn chế cần ghi nhận. Không suy ra xác suất đúng từ nhãn ổn định. Phạm vi filesystem và quyền truy cập không được tự xác nhận bằng allowlist tên file.

Chạy không gọi dịch vụ:
```bash
python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d --check
python3 replay_path_explanation.py
```

Replay tự chọn lượt hoàn tất mới nhất chỉ có nhánh Path v4 trong runs, in đường dẫn lượt được chọn. Có thể chỉ định `--run runs/TEN_LUOT` nếu muốn. Đọc snapshot nguồn và kiểm tra hash/dòng bằng chứng; giữ nguyên file kết quả và các thẩm định cũ. Tạo báo cáo so sánh riêng trong experiments/path_explanation_replay, không tự nhập vào UI hay đánh dấu đã review. Gửi JSON mới được in ra để kiểm tra.

Đã kiểm tra trên ba kết quả thực ngày 2026-10-21: không đổi nhãn/facts/evidence/missing_context/review, giữ nguyên lời giải thích gốc, chạy hàm trình bày hai lần cho cùng kết quả, từ chối nhãn không khớp facts. Đã kiểm tra cú pháp. Chưa chạy tích hợp trên máy Ubuntu người dùng.
