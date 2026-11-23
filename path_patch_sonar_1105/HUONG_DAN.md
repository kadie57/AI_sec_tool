# Quét so sánh PathCase01

Mục đích: ghi nhận SonarQube báo gì trên ba bản mã đã kiểm chứng: gốc, Qwen đề xuất và bản hiệu chỉnh. Đây là kiểm chứng bản sửa, không huấn luyện hoặc gọi lại AI.

## Chạy

Giải nén vào `~/AI_sec_tool`, tạo thư mục `path_patch_sonar_1105`, rồi chạy:

```bash
docker start sonarqube-db sonarqube
cd ~/AI_sec_tool/path_patch_sonar_1105
python3 rescan.py
```

Nếu chưa có `SONAR_TOKEN`, chương trình hỏi token và không hiện ký tự khi nhập. Dùng **User token** của tài khoản có quyền đọc project_1, tạo project, phân tích và gán Quality Profile. Token chỉ dành cho project_1 có thể không đủ quyền. Không gửi token cho người khác.

Chương trình dùng SonarScanner đã có trên máy. Nếu không tìm được, đặt `SONAR_SCANNER_PATH` thành đường dẫn tuyệt đối tới file `bin/sonar-scanner` hiện dùng rồi chạy lại. Không cần bật Ollama, Joern hoặc giao diện Flask.

Có thể chạy `python3 rescan.py --check` để kiểm tra file/công cụ trước, không gọi dịch vụ.

## Chương trình làm gì?

1. Đối chiếu hash ba nguồn với kết quả kiểm thử bạn gửi; biên dịch bản sao.
2. Đọc Java Quality Profile của project_1 và kiểm tra PATH_TRAVERSAL_IN đang bật.
3. Tạo ba project **private**, tên bắt đầu bằng `pathpatch_`, rồi gán cùng Java Quality Profile. Không đổi rule trong profile.
4. Quét từng bản, đợi task hoàn tất, xác minh mã trên server khớp và lấy đủ trang cảnh báo.
5. Nếu mã gốc không tái hiện cảnh báo mục tiêu, dừng để kiểm tra cấu hình, không coi các bản sửa là thành công.
6. Lưu `work/comparison.json` cùng log và checkpoint.

**Chạy xong, gửi `work/comparison.json`.** Nếu lỗi, gửi nội dung lỗi và log được chỉ ra; không gửi token. Giữ Terminal mở trong lúc quét. Chạy lại bỏ qua các bản đã lưu kết quả; nếu scanner bị ngắt trước khi có task ID, chương trình dừng để đối chiếu thay vì tự quét lặp.

Gói không sửa `Clean_Code` gốc, project_1, ứng dụng hoặc kết quả AI. Ba project kiểm chứng được giữ trên SonarQube để đối chiếu. Gói cần được chạy trên cùng máy chứa SonarQube localhost.

## Diễn giải kết quả

- Kết quả bạn gửi: cả ba nguồn biên dịch được trên Java 21; 12 ca kiểm tra đạt kỳ vọng. Bản hiệu chỉnh chặn hai tình huống thay thế fixture có kiểm soát; bản Qwen đọc được dữ liệu ngoài ở cả hai.
- Mất cảnh báo SonarQube **không tự chứng minh đã hết lỗ hổng**: cách nhận diện API mở tệp có thể khác nhau. Phải đối chiếu cả mã và kiểm thử chức năng.
- Bản hiệu chỉnh là kết quả sau thẩm định, không phải đầu ra nguyên văn Qwen.
- Phép thử thay tệp/thư mục có chèn thao tác mô phỏng; không đo xác suất khai thác race tự nhiên.
- Chỉ thu thập Issues API; Security Hotspots riêng không nằm trong phép so sánh này.
- Điều kiện bản sửa: root/cha đáng tin cậy và filesystem hỗ trợ SecureDirectoryStream; chưa chứng minh mọi tình huống hard link, quyền truy cập hoặc race.

## Kiểm chứng công cụ

Công cụ được kiểm tra cú pháp và luồng điều phối bằng dịch vụ giả lập; kết quả SonarQube thật phải lấy từ máy bạn. Không có kết quả quét thật được dựng sẵn trong gói.

Tài liệu API đối chiếu:
- https://docs.sonarsource.com/sonarqube-server/extension-guide/web-api
- https://github.com/SonarSource/sonar-migration-tool/blob/main/API_ENDPOINTS.md

Chương trình đọc `/api/webservices/list` của máy đang chạy để kiểm tra giao diện API trước khi tạo project.
