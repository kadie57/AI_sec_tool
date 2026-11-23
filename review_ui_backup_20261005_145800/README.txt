SQL Review — bước 3: thẩm định cục bộ

Đặt thư mục review_ui trực tiếp trong ~/AI_sec_tool.
Chạy từ ~/AI_sec_tool:
  source .venv_review_ui/bin/activate
  python review_ui/app.py
Mở http://127.0.0.1:5050
Yêu cầu: Python 3.12, Flask 3.1.3, Ubuntu/Linux.

Vào lượt Hoàn tất > Xem cảnh báo > chọn file > đọc mã nguồn.
Bên dưới mã nguồn có form người thẩm định, kết luận và lý do.
Các lựa chọn: LIKELY_TP, LIKELY_FP, UNKNOWN. Không tự chọn nhãn AI.
Lưu vào reviews_ui.json trong chính thư mục lượt chạy.
Mỗi lần sửa thêm một phiên bản, giữ lịch sử. Không sửa ai_results.json.
Các bản thẩm định trước đây ngoài UI chưa được nhập vào giao diện này.
Tên người thẩm định là tự khai, chưa có đăng nhập hoặc xác minh danh tính.
Trang tổng quan tiếp tục đếm nhãn AI ban đầu, không đếm nhãn thẩm định.

Chỉ cho lưu khi lượt COMPLETED, nguồn có hash khớp và bản ghi được hỗ trợ.
Hai tab cùng sửa: tab cũ bị từ chối; tải lại và đối chiếu trước khi lưu.
Khởi động lại server: tải lại trang để lấy biểu mẫu mới. Kết quả vẫn còn.
Sao lưu dữ liệu: giữ cả thư mục runs và eval_sql89_new_v1/runs.
Chạy local 127.0.0.1; đây là ứng dụng demo một người dùng.
Không import pipeline, không quét hoặc gọi mô hình.
