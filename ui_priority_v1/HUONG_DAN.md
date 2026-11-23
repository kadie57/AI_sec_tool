# Danh sách ưu tiên xử lý · v1

Gói dành cho giao diện đã cài `ui_report_v1` và xuất PDF được. Không cài thêm thư viện.

## Mục đích

Giúp chọn cảnh báo cần xem trước từ kết quả đã lưu. Xếp thứ tự bằng quy tắc minh bạch, dùng đề xuất hệ thống và thẩm định hợp lệ; đây không phải một lượt AI đánh giá mức độ nghiêm trọng hoặc khả năng khai thác.

| Nhóm | Hành động |
| --- | --- |
| 1 · Xử lý trước | LIKELY_TP đã thẩm định: lập phương án sửa; mới là đề xuất: thẩm định sớm. |
| 2 · Cần làm rõ | Bổ sung ngữ cảnh, xử lý dữ liệu thiếu, kiểm tra lỗi hoặc mâu thuẫn. |
| 3 · Xác minh cảnh báo giả | Hệ thống đề xuất LIKELY_FP nhưng chưa có thẩm định hợp lệ. |
| 4 · Đã thẩm định cảnh báo giả | Giữ bằng chứng và theo dõi khi mã nguồn/ngữ cảnh thay đổi. |
| Ngoài phạm vi tự động | Cảnh báo bị bỏ qua hoặc rule chưa hỗ trợ; xem riêng trong SonarQube. |

Nhãn UNKNOWN không có nghĩa an toàn. Nhãn AI, nhãn hệ thống và nhãn người thẩm định được hiển thị riêng. Thẩm định chỉ được dùng khi khớp bản ghi, lượt hoàn tất và hash mã nguồn. Trong nhóm đầu, LIKELY_TP đã thẩm định đứng trước đề xuất chưa thẩm định; các mục ngang nhau sắp theo đường dẫn và dòng mã. Danh sách chỉ áp dụng cho một lượt chạy, không gộp các lượt thành lỗi độc lập.

## Cài đặt

1. Dừng giao diện Flask bằng Ctrl+C ở terminal đang chạy UI. Nếu đang quét/phân tích, đợi tác vụ đó hoàn tất.
2. Giải nén ZIP vào `~/AI_sec_tool`, để có `~/AI_sec_tool/ui_priority_v1/install.py`.
3. Kiểm tra và cài:

```bash
cd ~/AI_sec_tool
source .venv_review_ui/bin/activate
python ui_priority_v1/install.py --check
python ui_priority_v1/install.py
python review_ui/app.py
```

Chỉ chạy bước cài khi đã thấy `INSTALL_CHECK_OK`. Trình cài đối chiếu SHA256, sao lưu các file thay đổi dưới `backups/ui_priority_<thời điểm>`, rồi cập nhật UI. Nếu có thông báo file khác bản, gửi nguyên văn thông báo để đối chiếu; không bỏ qua kiểm tra hash. Gói không sửa pipeline, prompt, mã Java, kết quả hoặc lịch sử thẩm định. Cài lại cùng gói sẽ dừng vì file đích không còn là bản trước cập nhật.

## Sử dụng

Mở `http://127.0.0.1:5050` → chọn lượt chạy → **Ưu tiên xử lý**. Mỗi cảnh báo có lý do xếp nhóm, bước tiếp theo và **Mở bằng chứng**. Có bộ lọc nhóm và xuất CSV đúng nhóm đang chọn. Sau khi lưu thẩm định, quay về và tải lại danh sách để thấy thay đổi.

Không cần khởi động SonarQube hoặc Ollama để xem kết quả đã lưu trên trang này. Chỉ cần Flask đang chạy và còn đủ tệp dữ liệu.

Với lượt 3 mẫu đã thẩm định trước đây, nếu dữ liệu vẫn khớp: PathCase01 ở “Xử lý trước”; Trial03 và CommandCase02 ở “Đã thẩm định cảnh báo giả”. AI gốc của CommandCase02 vẫn là UNKNOWN.

## Kiểm tra tự động tùy chọn

```bash
python ui_priority_v1/test_priority.py
```

Các kiểm tra dùng dữ liệu giả lập trong thư mục tạm, không quét hoặc gọi AI. Chúng kiểm tra thứ tự xử lý, thẩm định hết hiệu lực, lỗi dữ liệu, phân biệt bỏ qua/UNKNOWN, bộ lọc, CSV, liên kết chi tiết và cập nhật sau thẩm định.

## Phạm vi báo cáo khóa luận

Chỉ sau khi cài và thử thành công, có thể bổ sung: “Hệ thống cung cấp danh sách ưu tiên công việc dựa trên kết quả phân tích và thẩm định đã lưu. Mỗi cảnh báo có lý do xếp nhóm và hành động tiếp theo. Thẩm định hợp lệ được ưu tiên, trong khi các trường hợp thiếu dữ liệu hoặc mâu thuẫn được giữ lại để làm rõ.”

Không mô tả tính năng này là mô hình học xếp hạng, đánh giá CVSS, hoặc AI tự xác định khả năng khai thác. Chưa có quản lý người phụ trách, hạn xử lý, tự tạo bản vá hay tự đóng cảnh báo trên SonarQube.
