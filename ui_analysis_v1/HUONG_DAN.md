# Chạy phân tích từ giao diện — bản 1

## Cài đặt trên Ubuntu

Giải nén để có ~/AI_sec_tool/ui_analysis_v1/install.py.
Dừng server Flask cũ bằng Ctrl+C; chờ các tác vụ phân tích đang chạy hoàn tất.

```bash
cd ~/AI_sec_tool
python3 ui_analysis_v1/install.py
source .venv_review_ui/bin/activate
python -m pip install -r ui_analysis_v1/requirements-ui.txt
python review_ui/app.py
```

Mở http://127.0.0.1:5050 → Bắt đầu phân tích / Xem tác vụ.
Chọn lượt quét và chọn một file trước. Bấm **Kiểm tra cấu hình — không gọi AI**.
Nếu kiểm tra đạt, quay lại chọn file và bấm **Bắt đầu phân tích bằng AI**.
Sau khi hoàn tất, bấm **Mở kết quả và thẩm định**; dùng UI hiện có để xem code,
lưu thẩm định, xem thống kê và tải CSV.

Việc kiểm tra offline đạt không chứng minh Docker/Ollama đang hoạt động.
Phân tích thật cần Docker/Joern và Ollama sẵn sàng. Pipeline và worker dùng Python
của môi trường đang chạy Flask; requirements ở trên bổ sung requests cho backend.
Phân tích dữ liệu đã thu thập không cần nhập Sonar token vào giao diện.
Nếu dùng biến môi trường riêng (OLLAMA_URL, JOERN_IMAGE...), đặt trước khi bật Flask.

## Phạm vi phiên bản

- Chọn các component có cảnh báo thuộc registry ba nhánh hiện tại.
- Kiểm tra cấu hình trước mọi lượt phân tích. Giới hạn tối đa AI hiển thị theo số cảnh báo.
- Một tác vụ UI tại một thời điểm; dùng worker riêng, không chặn server Flask.
- Nhật ký tự cập nhật mỗi 5 giây, lưu tại .review_jobs; đóng tab không dừng tác vụ.
- Khởi động lại Flask vẫn xem được trạng thái worker. Tắt máy/worker chết không tự gọi lại AI.
- Không có nút hủy ở bản này. Không tự dùng --retry-incomplete. Khi cảnh báo dở dang,
  xử lý checkpoint qua terminal sau khi xem nhật ký.
- Timeout kiểm tra 2 phút, phân tích 6 giờ; timeout có thể để lại cảnh báo dở dang.
- Nhãn hoàn tất là hoàn tất tiến trình, không bảo đảm tất cả cảnh báo có kết luận hoặc không có lỗi cấp cảnh báo.
- Không quét SonarQube mới từ UI, không sửa prompt/model/nhãn hoặc tự đóng cảnh báo.
- UI chỉ dành cho localhost Ubuntu, chưa có đăng nhập nhiều người dùng hoặc triển khai Internet.

## Giữ dữ liệu cấu hình

Nhánh SQL hiện còn đọc baseline trong runs/experiments. Không xóa các thư mục đó.
Bản ZIP nguồn không chứa baseline nên không phải gói triển khai độc lập.
Nếu nhật ký báo thiếu baseline, lưu thông báo để xử lý; không bỏ qua kiểm tra hash.

## Kiểm thử và giới hạn xác nhận

Kiểm thử tự động dùng pipeline giả: kiểm tra offline, thành công/thất bại, ngăn chạy trùng,
chọn component sai/đường dẫn sai, CSRF, tác vụ gián đoạn, che token trong log,
lưu thẩm định, xung đột revision, xuất CSV và giữ nguyên ai_results.json.
Các route/template được kiểm tra bằng Flask test client; chưa xác nhận bố cục qua trình duyệt thật trong môi trường đóng gói.
Đây không phải lượt đánh giá AI mới. Chưa chạy Ollama/Sonar/Joern trên laptop người dùng.

## Hoàn tác

Installer in đường dẫn backups/ui_analysis_... chứa app.py và templates/index.html cũ.
Dừng Flask và bảo đảm không có tác vụ đang chạy. Chép hai file đó về đúng vị trí
review_ui/app.py và review_ui/templates/index.html, rồi bật Flask lại.
Các file mới có thể giữ lại vì app cũ không dùng; kết quả, lịch sử thẩm định và .review_jobs không bị xóa.
