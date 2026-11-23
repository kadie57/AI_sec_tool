# Hiển thị kết quả kiểm chứng bản sửa

Gói bổ sung cho ứng dụng đã cài ui_patch_v1. Trang Đề xuất sửa sẽ có khối “Kết quả kiểm chứng đã lưu” cho đúng bản đề xuất PathCase01 đã gửi ngày 05/11/2026. Khối hiển thị kiểm thử bản hiệu chỉnh v2, so sánh cảnh báo giữa bốn phiên bản và mã nguồn hiệu chỉnh.

Đây là chức năng đọc hồ sơ đã có, chưa phải nút tự kiểm thử mọi bản sửa. Các đề xuất khác không được gắn kết quả này. Hồ sơ khớp toàn bộ JSON đề xuất, hash nguồn và hash tệp bằng chứng. Hash kiểm tra tính nhất quán, không phải chữ ký chứng minh nguồn gốc. Nếu dữ liệu thay đổi, khối báo lỗi hoặc không hiển thị.

## Cài đặt

Chờ tác vụ UI hoàn tất rồi Ctrl+C ở terminal chạy Flask. Giải nén ZIP vào ~/AI_sec_tool, sau đó:

```bash
cd ~/AI_sec_tool
source .venv_review_ui/bin/activate
python ui_patch_evidence_v1/install.py --check
```

Khi có INSTALL_CHECK_OK:

```bash
python ui_patch_evidence_v1/install.py
python review_ui/app.py
```

Nếu báo file khác phiên bản, gửi nguyên lỗi; không sửa hash hoặc chép đè thủ công. Trình cài sao lưu các file thay đổi dưới backups và giữ dữ liệu phân tích, thẩm định, đề xuất AI nguyên vẹn.

## Xem kết quả

Mở http://127.0.0.1:5050 → lượt có PathCase01 → Đề xuất sửa lỗi. Chọn đúng bản đề xuất đã dùng kiểm chứng nếu có nhiều bản trong lịch sử. Cuộn xuống “Kết quả kiểm chứng đã lưu”.

Cần thấy: chức năng 14/14; chặn hai tình huống thay tệp/thư mục; tài nguyên 5/5; Path Traversal còn 1; ba cảnh báo S2095, S3776, S2293 của bản v1 đã hết ở v2. Bảng chỉ tổng hợp bốn rule theo dõi, không phải toàn bộ cảnh báo.

Nếu không thấy khối mới, thử Ctrl+F5 và kiểm tra đúng bản trong lịch sử. Không bấm yêu cầu AI mới để lấy lại kết quả: hồ sơ này chỉ thuộc bản đề xuất đã kiểm chứng. Không cần bật Ollama, SonarQube hoặc chạy Java để xem trang.

Bản hiệu chỉnh v2 chưa áp dụng vào Clean_Code; mẫu gốc được giữ làm đối chứng. Kết quả kiểm thử không tự đổi nhãn thành FP, không đóng cảnh báo. Tài nguyên cần SecureDirectoryStream, gốc/cha tin cậy; giới hạn độ sâu 64 thư mục. Hai thay thế được mô phỏng có kiểm soát, không phải đo race tự nhiên. Bản v2 là bản hiệu chỉnh có trợ giúp, không phải đầu ra nguyên văn Qwen.
