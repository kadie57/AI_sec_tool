# Kiểm tra bản hiệu chỉnh PathCase01 v2

## Vì sao cần bước này?

Lượt quét bạn đã gửi (`comparison_previous.json`) hoàn tất ngày 05/11/2026:

| Cảnh báo | Mã gốc | Qwen đề xuất | Bản hiệu chỉnh v1 |
|---|---:|---:|---:|
| `findsecbugs:PATH_TRAVERSAL_IN` | 1 | 1 | 1 |
| `java:S2095` — quản lý tài nguyên | 0 | 0 | 1 |
| `java:S3776` — độ phức tạp | 0 | 0 | 1 |
| `java:S2293` — cú pháp generic | 0 | 0 | 1 |

S2095 chưa tự chứng minh có rò rỉ tài nguyên: bản v1 có xử lý đóng thủ công,
nhưng khó theo dõi. Bản v2 chuyển việc mở/đóng thư mục và tệp về
`try-with-resources`, chia hàm ngắn và đọc dữ liệu trước khi rời phạm vi tài nguyên.
Vẫn giữ kiểm tra đường dẫn chuẩn hóa nằm trong thư mục gốc và mở từng thành phần
qua `SecureDirectoryStream` với `NOFOLLOW_LINKS`.

Đây là bản hiệu chỉnh có trợ giúp, **không phải đầu ra nguyên văn của Qwen**.
Chưa khẳng định các cảnh báo trên sẽ hết: cần kết quả SonarQube thực tế của bản v2.
Không đổi/tắt rule để làm giảm số cảnh báo.

## Chạy trên Ubuntu

1. Giải nén ZIP vào `~/AI_sec_tool`. Thư mục mới là `path_patch_refine_1105`.
2. Mở Terminal và chạy:

```bash
docker start sonarqube-db sonarqube
cd ~/AI_sec_tool/path_patch_refine_1105
python3 run.py
```

Gói dùng thư viện chuẩn Python, Java JDK và SonarScanner đang có. Không cần Flask
hoặc Ollama. Nếu SonarQube vừa bật mà chưa sẵn sàng, đợi trang localhost:9000 mở
được rồi chạy lại đúng lệnh. Nếu được hỏi token, dùng SonarQube **User token** có
quyền tạo/quét project và gán Quality Profile; khi nhập không hiện ký tự là bình thường.
Không gửi token trong cuộc trò chuyện.

Chương trình tự thực hiện:

1. Kiểm thử bản v2 bằng dữ liệu giả trong thư mục tạm. Không đọc `/var/www` thật.
2. Nếu đạt, tạo **một project kiểm chứng riêng**, dùng cùng Java Quality Profile
   của lượt trước và quét **chỉ bản v2**. Không sửa `project_1`, profile gốc,
   `Clean_Code`, backend, UI hay kết quả AI.
3. Ghép kết quả mới với ba kết quả cũ đã lưu; không chạy lại ba bản cũ và không gọi AI.

Nếu muốn chỉ kiểm thử offline:

```bash
python3 run.py --check
```

Sau khi hoàn tất, gửi file:

```text
~/AI_sec_tool/path_patch_refine_1105/work/comparison_v2.json
```

File phụ `work/verification_v2.json` chứa chi tiết kiểm thử trên máy bạn.
Chạy lại cùng lệnh sẽ dùng lại kiểm thử hợp lệ, tiếp tục task đã nộp hoặc trả kết
quả đã hoàn tất. Nếu scanner dừng trước khi ghi task, chương trình dừng để đối
chiếu, không tự gửi thêm lượt quét. Giữ thư mục `work`.

Nếu không tìm thấy scanner, đặt đường dẫn bản bạn đang dùng rồi chạy lại:

```bash
export SONAR_SCANNER_PATH="$HOME/Downloads/sonar-scanner-8.0.1.6346-linux-x64/bin/sonar-scanner"
python3 run.py
```

## Bản v2 thay đổi gì và đã được thử ra sao?

- `sources/reviewed_v2.java.txt`: ứng viên mới, chưa áp dụng vào dự án.
- `sources/reviewed_v1.java.txt`: bản v1 giữ nguyên để đối chiếu.
- `reviewed_v1_to_v2.patch`: khác biệt giữa hai bản.
- `verification_reference.json`: kiểm thử ở môi trường chuẩn bị gói, không phải
  kết quả mới trên máy bạn và không được dùng làm checkpoint.

Kiểm thử gồm 12 tình huống chức năng cũ, 2 tình huống giới hạn độ sâu, 2 tình
huống thay tệp/thư mục bằng liên kết ra ngoài sau bước kiểm tra và 5 tình huống
đóng tài nguyên/truyền ngoại lệ. Hai tình huống thay thế được chèn có kiểm soát,
không phải phép đo tỷ lệ khai thác race condition tự nhiên. Bộ thử tài nguyên
dùng đối tượng giả để kiểm tra lệnh đóng và ngoại lệ, không đo rò rỉ descriptor
trong hệ điều hành.

Thay đổi hành vi rõ ràng: bản v2 cho phép tối đa **64 thư mục con** trên đường
dẫn chuẩn hóa; sâu hơn sẽ bị từ chối, nhằm giới hạn đệ quy và số thư mục mở đồng
thời. Gói thử cả 64 (được đọc) và 65 (bị từ chối). Bản v1 chưa có giới hạn này.

Điều kiện áp dụng: thư mục gốc cấu hình và các thư mục cha phải đáng tin cậy;
hệ thống tệp phải hỗ trợ `SecureDirectoryStream`. Nếu không hỗ trợ thì báo lỗi
và không đọc tệp. Hard link, kiểm soát quyền theo nghiệp vụ và mọi lịch thay đổi
hệ thống tệp có thể xảy ra chưa được chứng minh an toàn bởi bộ thử này.

Tài liệu API: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/SecureDirectoryStream.html

## Kết thúc bước này như thế nào?

Đối chiếu kết quả chạy thật với bản v1: kiểm thử còn đạt không, cảnh báo S2095,
S3776 và S2293 còn không, PATH_TRAVERSAL_IN chỉ vào đâu. Cảnh báo còn tồn tại
cần được giải thích từ mã nguồn; cảnh báo biến mất không tự chứng minh an toàn.
Sau đó mới chọn ứng viên để áp dụng và ghi số liệu thực tế vào khóa luận.

Ba kết quả cũ được tái sử dụng; gói kiểm tra server, profile và dấu vân tay các
rule đang bật khớp lần trước trước khi quét. Phiên bản plugin không được ghi
dấu vân tay độc lập ở kết quả cũ. Gói thu thập Issues API, chưa thu thập riêng
Security Hotspots. Không có số liệu độ chính xác tổng quát hay cam kết an toàn 100%.
