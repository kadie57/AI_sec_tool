# Sửa việc bỏ nhầm ngữ cảnh còn thiếu

Gói này cập nhật bốn file Python trong dự án **AI_sec_tool hiện tại**. Installer kiểm tra hash và sao lưu file cũ trước khi thay. Mã Java, các lượt chạy cũ và nhãn AI nguyên bản được giữ lại.

## Chạy ngay

Tải `sql_source_merge_guard_v1.zip` vào Downloads, rồi chạy:

```bash
cd ~/AI_sec_tool
unzip ~/Downloads/sql_source_merge_guard_v1.zip -d .
python3 sql_source_merge_guard_v1/install.py
python3 remerge_sql_sources.py --check
```

Khi thấy `MERGE_CHECK_OK`, chạy:

```bash
python3 remerge_sql_sources.py --run
```

Đây là phép ghép lại bằng Python trên dữ liệu đã lưu, **không gọi AI, SonarQube hoặc Joern**. Không cần khởi động các dịch vụ đó.

Với đúng bộ kết quả đã gửi, dự kiến có một thay đổi:

```text
BenchmarkTest02186.java: LIKELY_TP -> UNKNOWN
```

Kết quả hệ thống sau phép ghép: 4 `LIKELY_TP`, 1 `LIKELY_FP`, 3 `UNKNOWN`. Đây là điều chỉnh chính sách để giữ lại thiếu sót về ngữ cảnh, không phải một lượt suy luận AI mới. Hai lỗi bằng chứng nguồn vẫn được ghi nhận.

Cuối lệnh có dòng `ZIP CẦN GỬI`. File ZIP chứa đầu ra mới cùng bản sao bằng chứng cũ để đối chiếu. Gửi lại file đó nếu kết quả trên máy khác dự kiến hoặc nếu có lỗi. Không cần chạy lại `recheck_sql_source.py --run` ở bước này.

Nếu thư mục kết quả đã được chuyển vị trí, thêm `--previous-run ĐƯỜNG_DẪN` vào cả hai lệnh. Mặc định là:

```text
experiments/sql_source_recheck_v1/multi-owasp-holdout-20261115T151839Z-b04660-688bdde398e1-47bf30f61290
```

## Sửa gì và vì sao

Ở mẫu 02186, bước SQL yêu cầu nội dung `doSomething`, `ThingInterface` và `ThingFactory`. Source audit lại coi yêu cầu này là câu hỏi về nguồn và bỏ nó vì thấy HTTP request. Biết nguồn HTTP chưa cho biết helper có truyền nguyên giá trị hay biến đổi/bảo vệ dữ liệu.

Danh sách `missing_context` cũ chưa tách thành trường nguồn và trường SQL. Bản sửa dùng quy tắc bảo thủ: chỉ một số câu hỏi đơn thuần về nguồn của một biến/tham số mới đủ điều kiện được source audit giải quyết. Câu khác, kể cả nội dung mơ hồ, được giữ lại. Quy tắc dựa vào dạng câu, không dùng tên mẫu, nhãn OWASP hoặc kết luận mong muốn. Đây không phải bộ hiểu ngôn ngữ tổng quát, nên có thể giữ lại một số mục vốn đã giải quyết nhưng viết theo cách khác.

Bằng chứng và đánh giá `resolved` nguyên bản của mô hình vẫn được lưu. Kết quả ghép ghi riêng `model_reported_resolved`, `merge_disposition` và phiên bản chính sách. Trong lượt ghép ngoại tuyến, `ai_verdict` giữ đề xuất cũ, còn `combined_verdict`/`verdict` là kết quả của chính sách mới.

Bản sửa cũng cải thiện thông báo lỗi bằng chứng: thông báo sẽ nêu chính xác dòng sai, ví dụ dòng 45 trống, để lần sửa đầu ra sau có thông tin cụ thể. Chưa chạy Qwen mới để đo hiệu quả của thông báo này.

## Phần còn phải xử lý

- Mẫu 02088 và 02093: source audit dẫn dòng 45 trống; lần sửa đã lặp lại lỗi. Gói này giữ lỗi, không tự đoán dòng thay thế.
- Mẫu 02093: bước SQL cũ đọc sai nhánh `switch`; việc hiện ra `UNKNOWN` do lỗi bằng chứng không có nghĩa lỗi suy luận đã được sửa.
- Mẫu 02088 và 02186: cần cung cấp và phân tích các helper liên quan trước khi kết luận về tác động SQL.
- Mẫu 01558: đầu vào đi qua `SeparateClassRequest`; nội dung wrapper chưa có trong yêu cầu AI của lượt đã gửi.
- Mẫu 01311 và 02186: dòng 33 là khai báo phương thức, không phải lệnh đọc parameter ở dòng 43. Kiểm tra dòng tồn tại không chứng minh dòng đó hỗ trợ lời giải thích.

Xem `review_results.md` để đọc đối chiếu chi tiết. Các kết quả hiện tại là chẩn đoán sau khi xem bộ đánh giá, không phải một bộ holdout độc lập mới và không đại diện độ chính xác của toàn bộ 49 cảnh báo.

## Kiểm tra trước khi giao

Đã chạy năm kiểm thử mới và mười hai kiểm thử của bản trước với đầu ra mô phỏng; đã ghép lại đúng tám artifact thực bằng Python và kiểm tra không có lời gọi mạng trong phép ghép. Installer đã được thử trên bản sao dự án. Chưa gọi Qwen thật sau thay đổi này.
