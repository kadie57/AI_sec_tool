# Xuất báo cáo từ ứng dụng - ui_report_v1

Bước này bổ sung chức năng cho ứng dụng. Bạn chưa cần sửa báo cáo khóa luận
để cài hoặc dùng chức năng này.

## Chức năng mới

Ở trang chi tiết lượt chạy và trang thống kê có nút **Báo cáo toàn lượt · HTML / PDF**.
Trang báo cáo cho phép xem trước, tải một file HTML tự chứa định dạng để mở offline,
hoặc tải PDF trực tiếp. PDF có font tiếng Việt đi kèm, không cần cài trình duyệt
hay bộ chuyển đổi PDF trên máy chủ.

Nội dung gồm:

- Thông tin lượt chạy, thời gian, số cảnh báo và thống kê theo nhóm lỗi.
- Ba lớp kết quả: AI ban đầu, hệ thống kết hợp luật, người thẩm định.
- Giải thích, thông tin còn thiếu, ghi chú của người thẩm định và thời điểm lưu.
- Các dòng bằng chứng và tối đa hai dòng xung quanh, lấy từ snapshot mã đã kiểm tra hash.
- Issue ID, hash nguồn và dấu vết các file dữ liệu dùng để xuất.

Báo cáo xuất toàn bộ bản ghi của một lượt, không áp dụng bộ lọc ở trang thẩm định.
Khi hai phần giải thích AI/hệ thống giống hệt nhau, chúng được trình bày một lần
với nhãn nguồn rõ ràng. Các kết luận vẫn được giữ riêng.

## Cài đặt

Gói dành cho dự án đã cài ui_scan_v1 ngày 28/10. Trình cài kiểm tra đúng phiên bản
UI và tự sao lưu trước khi cập nhật. Nếu file đã bị sửa, trình cài dừng để đối chiếu.

1. Chờ tác vụ UI đang chạy hoàn tất. Dừng Flask bằng Ctrl+C ở terminal đang mở ứng dụng.
2. Giải nén ZIP để có `~/AI_sec_tool/ui_report_v1/install.py`.
3. Chạy:

```bash
cd ~/AI_sec_tool
source .venv_review_ui/bin/activate
python -m pip install -r ui_report_v1/requirements-report.txt
python ui_report_v1/install.py
```

Thư viện ReportLab dùng để tạo PDF. Cần mạng cho lần cài thư viện này.
Khi có `INSTALL_OK`, mở lại:

```bash
python review_ui/app.py
```

## Thử với kết quả đã có

1. Mở http://127.0.0.1:5050 và tải lại trang.
2. Mở lượt `multi-20261028T044150Z-8c8b72-824acdcd9ce2` có ba cảnh báo đã thẩm định.
3. Bấm **Báo cáo toàn lượt · HTML / PDF**.
4. Kiểm tra bảng ba lớp kết quả và thời gian toàn lượt, rồi bấm **Tải PDF**.
5. Mở PDF vừa tải. Có thể gửi file này để kiểm tra bản xuất thật từ laptop.

Không cần khởi động SonarQube/Ollama hay chạy lại AI để xuất báo cáo. Dữ liệu
được đọc từ kết quả và thẩm định đã lưu. Khi sửa thẩm định, cần xuất lại để có
báo cáo chứa nội dung mới.

## Quy tắc dữ liệu

- Không sửa nhãn AI, nhãn hệ thống, lịch sử thẩm định, mã nguồn hoặc cấu hình phân tích.
- UNKNOWN của các bản ghi SKIPPED/ABSTAINED không được cộng vào số UNKNOWN do AI đề xuất.
- Chỉ tính thẩm định mới nhất còn khớp bản ghi và snapshot nguồn. Nguồn không khớp
  thì báo rõ tình trạng, không xuất đoạn mã đó như bằng chứng đã xác minh.
- Lượt chưa hoàn tất được gắn thông báo dữ liệu hiện có, không coi là kết quả cuối.
- Nếu file thẩm định hỏng hoặc thiếu dữ liệu bắt buộc, báo lỗi thay vì tạo báo cáo
  có số liệu tưởng như hợp lệ.
- Thời gian toàn lượt không phải thời gian riêng của mô hình. Với lượt từ cảnh báo
  đã lưu, nó không gồm lần quét SonarQube trước đó hay thẩm định thủ công sau đó.
- Nhãn khớp thẩm định không được tự đổi thành tuyên bố độ chính xác chung.

## Kiểm tra bản cập nhật

Đã qua sáu nhóm kiểm tra offline: xem/tải HTML và PDF không gọi tiến trình phân tích,
không sửa dữ liệu cũ; nội dung mã/AI được escape; mã nguồn không khớp; file thiếu/hỏng;
phạm vi thống kê với lượt chưa hoàn tất và cảnh báo bị bỏ qua; hồi quy lưu thẩm định,
xuất CSV và các trang UI hiện có.

Đã dựng PDF thử với lời giải thích dài từ CSV đã cung cấp và kiểm tra trực quan
font tiếng Việt, bảng, đoạn mã và ngắt trang. Đây là kiểm tra chức năng xuất báo cáo,
không phải một lần chạy đánh giá AI mới. Cần kiểm tra bản xuất trên laptop sau khi cài.

Các kiểm tra dùng dữ liệu giả lập có thể chạy lại bằng:

```bash
python -m unittest discover -s ui_report_v1 -p test_report_export.py -v
```

Font DejaVu được đóng gói cùng thông báo bản quyền trong `review_ui/fonts/LICENSE-DejaVu.txt`.
