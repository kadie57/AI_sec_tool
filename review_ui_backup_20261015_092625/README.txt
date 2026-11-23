SQL Review — bước 4

Chức năng mới
- Thống kê toàn lượt: tổng / đã thẩm định / chưa thẩm định / không đủ điều kiện.
- Bộ lọc thẩm định kết hợp với trạng thái xử lý và nhãn AI.
- CSV xuất đúng danh sách theo bộ lọc đã áp dụng, có BOM UTF-8 để đọc tiếng Việt.
- CSV tách nhãn AI và nhãn người thẩm định, kèm thông tin truy vết và phiên bản mới nhất.
- Giữ bộ lọc sau khi lưu; nếu lọc Chưa thẩm định, bản ghi vừa lưu sẽ rời danh sách.
- Biểu mẫu thẩm định hiển thị rõ file và dòng.

Cách cập nhật trên Ubuntu (không chạy lại AI)
1. Dừng Flask bằng Ctrl+C ở Terminal đang chạy.
2. Sao lưu mã UI:
   cd ~/AI_sec_tool
   cp -a review_ui "review_ui_backup_$(date +%Y%m%d_%H%M%S)"
3. Giải nén ZIP này vào ~/AI_sec_tool, cho phép thay thế các file trong review_ui.
   ZIP chỉ chứa mã review_ui; không chứa runs hay reviews_ui.json.
4. Khởi động:
   source .venv_review_ui/bin/activate
   python -m flask --app review_ui.app run --host 127.0.0.1 --port 5050
5. Mở http://127.0.0.1:5050 và Ctrl+Shift+R.

Cách kiểm tra
- Chọn lượt Probe đã có hai thẩm định.
- Đặt Trạng thái=Tất cả, Thẩm định=Đã thẩm định, bấm Lọc.
- Probe21 và Probe23 phải còn nhãn đã lưu (nếu chưa có thêm thay đổi).
- Xuất CSV; số dòng dữ liệu bằng số bản ghi trên danh sách đã lọc.
- Thống kê ở đầu trang luôn tính toàn lượt, không đổi theo bộ lọc.

Ý nghĩa thống kê
Chỉ bản ghi có trạng thái AI_PROPOSED, ANALYZED hoặc ABSTAINED, thuộc lượt
COMPLETED có analysis_id và mã nguồn khớp SHA256 mới đủ điều kiện thẩm định.
Đã thẩm định nghĩa là có lịch sử UI khớp chính xác bản ghi và mã nguồn còn hợp lệ.
Không đủ điều kiện bao gồm SKIPPED, thiếu/sai mã nguồn, lượt chưa hoàn tất.
Thống kê không phải độ chính xác của AI. UNKNOWN không đồng nghĩa mã an toàn.
Các file reviewed_results cũ ngoài UI chưa được nhập tự động.
CSV có thể chứa nhãn thẩm định cũ ở bản ghi không đủ điều kiện; luôn xem
review_state và review_block. CSV chỉ xuất phiên bản thẩm định mới nhất;
lịch sử đầy đủ vẫn nằm trong reviews_ui.json.

Dữ liệu và giới hạn
- Không sửa ai_results.json, manifest.json hoặc mô hình/pipeline AI.
- Lịch sử vẫn lưu riêng tại reviews_ui.json trong từng lượt chạy.
- CSV không tự kết luận thay cho người kiểm tra; không đóng cảnh báo SonarQube.
- Các ô văn bản có ký tự mở đầu công thức được thêm dấu nháy đơn khi xuất CSV.
- Chỉ phục vụ ứng dụng local tại 127.0.0.1; chưa phải triển khai nhiều người dùng.
