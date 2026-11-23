# Bộ thử SQL Injection — pilot 1

## Mục tiêu của lần chạy này

Chỉ thu thập cảnh báo SonarQube/Find Security Bugs trên 8 mẫu cố định. Chưa chạy Joern hoặc AI.
Mốc hoàn thành: có issues.json và manifest.json của lần quét; đối chiếu đủ 8 mẫu để biết
mẫu nào có cảnh báo SQL, mẫu nào không có, và có cảnh báo giả ứng viên hay không.

## Cài vào dự án hiện tại

Giải nén ZIP tại ~/AI_sec_tool. Cấu trúc phải là Clean_Code/pilot_sql89/Trial01.java ... Trial08.java,
và pilot_sql89_notes/ nằm ngoài Clean_Code. Gói không chứa bản thay thế script Python hoặc các mẫu cũ.
Không chép answer_key.json vào code hoặc prompt gửi AI.

Chạy tại ~/AI_sec_tool:

```bash
python3 master_pipeline.py --collect-only
```

Lệnh dùng script hiện có, biên dịch Java bằng javac, quét SonarQube rồi lấy cảnh báo.
Không gọi main của các mẫu, không cần tạo database hay cài JDBC driver chỉ để biên dịch/quét.
Phải có SONAR_TOKEN trong Terminal và SonarQube đang chạy. Nếu chưa đặt token:

```bash
read -rsp 'Sonar token: ' SONAR_TOKEN
echo
export SONAR_TOKEN
```

Kết quả nằm trong runs/<mã-lần-chạy>/issues.json và manifest.json.
Script vẫn quét cả các mẫu cũ trong Clean_Code; khi đối chiếu bộ này chỉ lấy đường dẫn
Clean_Code/pilot_sql89/. Không cần xóa hoặc di chuyển mẫu cũ.

## Đáp án và giới hạn

- Trial01, Trial05, Trial08: dữ liệu args được đưa vào cú pháp SQL không bảo vệ.
- Trial02: bind giá trị vào mẫu SQL cố định.
- Trial03: chỉ nhận toàn bộ chuỗi ASCII chữ/số/_ có độ dài 1–32.
- Trial04: chỉ ghép giá trị int sau Integer.parseInt.
- Trial07: chọn tên bảng từ hai hằng cố định, không nối trực tiếp args.
- Trial06: chỉ có tham số hàm, chưa rõ caller; cần giữ trạng thái thiếu ngữ cảnh.

Lý do, vị trí JDBC và SHA256 từng file nằm trong answer_key.json. Đây là đáp án dự kiến
của bộ mẫu tự xây dựng, cần người hướng dẫn hoặc người khác kiểm tra độc lập trước khi dùng
làm ground truth chính thức. Các nhãn không phụ thuộc câu trả lời AI.

Chưa chạy SonarQube trên bộ mẫu này: không hứa scanner sẽ cảnh báo các mẫu được bảo vệ.
Nếu không có cảnh báo SQL trên một mẫu được bảo vệ, ghi nhận kết quả đó; không tự tạo cảnh báo.
Nếu cả bộ không có cảnh báo giả, chốt rằng bộ pilot chưa đo được khả năng lọc FP;
bước sau dùng tập dữ liệu công khai hoặc ca thực tế đã được xác minh, không lặp vô hạn việc sửa prompt.

## Quy tắc đối chiếu

1. Kiểm tra hash trong manifest của lần quét khớp answer_key.json để tránh dùng kết quả cũ.
2. Lọc đúng hai rule JDBC trong answer_key.json; cảnh báo System.out/SELECT */code smell không phải SQLi.
3. Đối chiếu từng cảnh báo theo file và vị trí SQL. Nếu vị trí khác dự kiến, đọc lại code trước khi gán nhãn.
4. SAFE + có cảnh báo JDBC phù hợp: ứng viên FP cần xác minh; UNSAFE + có cảnh báo: ứng viên TP.
5. UNSAFE không có cảnh báo: hạn chế phát hiện của scanner trên mẫu đó, không quy cho AI.
6. Trial06 không xếp vào mẫu an toàn hay lỗi thật khi thiếu nguồn; tách riêng kiểm tra UNKNOWN.
7. Giữ tất cả kết quả. Không bỏ mẫu khó hoặc UNKNOWN để làm đẹp số liệu.

## Khi thử AI sau bước thu thập

Giữ nguyên model, prompt v4 và cấu hình cho cả lượt. Giữ cả raw_output và kết luận sau validator,
để không nhầm AI tự trả UNKNOWN với chương trình chặn câu trả lời không nhất quán.
Không dùng 8 mẫu pilot này vừa chỉnh prompt vừa báo cáo là đánh giá trên tập kiểm thử độc lập.
Chưa có số liệu chứng minh độ chính xác hoặc mức giảm FP của công cụ.

## Kiểm tra gói

Mã dùng Java chuẩn và JDBC trong JDK. Nơi tạo gói không có javac nên chưa xác minh biên dịch tại đây;
bước [1/4] của master_pipeline.py sẽ kiểm tra trên máy bạn trước khi quét. Không cần chạy các lớp Java.
