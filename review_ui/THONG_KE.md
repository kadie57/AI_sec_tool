# Trang thống kê

Mở một lượt chạy, bấm “Thống kê toàn lượt chạy”. Trang chỉ đọc dữ liệu,
không gọi SonarQube/Ollama, không sửa kết quả hoặc lịch sử thẩm định.

Nhãn AI và nhãn hệ thống chỉ đếm AI_PROPOSED/ANALYZED.
SKIPPED và ABSTAINED được đếm riêng. Nhãn thẩm định dùng revision mới nhất
khớp nguyên bản ghi và hash mã nguồn, giống trang thẩm định hiện có.
Thiếu artifact sẽ làm thẩm định không đủ điều kiện, không tự tin dùng CSV thay thế.
Thời gian là khoảng giữa hai mốc manifest, không phải thời gian riêng của AI.

Cài đặt: sao lưu review_ui hiện tại, giải nén thư mục review_ui vào AI_sec_tool,
khởi động lại Flask bằng .venv_review_ui/bin/python review_ui/app.py.
Không thay đổi runs hoặc eval_sql89_new_v1/runs.
