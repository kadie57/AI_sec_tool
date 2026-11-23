# Cập nhật giải thích – 20/10/2026

Giao diện đưa giải thích đã lưu ở llm_stage2.json lên phần Cơ sở của kết luận,
hiển thị riêng kiểm tra nguồn (source_audit_facts), số dòng của từng bước,
và báo rõ khi nhãn hoặc nhận định nguồn ở bước 2 bị bước sau điều chỉnh.
Lời giải thích được giữ nguyên văn, không tạo thêm kết luận bằng quy tắc theo tên mẫu.
Kết quả tổng hợp gốc vẫn xem được trong mục thu gọn. Các nhánh không có artifact
bước 2 tiếp tục hiển thị giải thích kết quả gốc.

Đây là cập nhật trình bày, không thay đổi mô hình, prompt, kết quả hay lịch sử
thẩm định; không tự sửa các câu diễn đạt chưa chính xác trong bản phân tích AI.
CSV tiếp tục xuất giải thích đã lưu trong kết quả, không thay bằng văn bản mới.

Cài đặt (dừng Flask bằng Ctrl+C trước):
1. Sao lưu review_ui hiện có.
2. Giải nén ZIP vào ~/AI_sec_tool (ZIP chứa thư mục review_ui).
3. Chạy: .venv_review_ui/bin/python review_ui/app.py
4. Mở http://127.0.0.1:5050 và tải lại trang Trial07 bằng Ctrl+F5.

Kiểm tra: hai mục Phân tích SQL và cơ chế bảo vệ / Kiểm tra riêng nguồn đầu vào
hiện trực tiếp dưới kết luận. Trial07 phải có đoạn switch giới hạn users/accounts.
Không cần chạy lại AI để xem nội dung đã lưu. Nhãn thẩm định đã lưu vẫn giữ nguyên.
