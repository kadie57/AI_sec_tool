# Cập nhật kiểm tra nguồn SQL

Gói này cập nhật dự án **AI_sec_tool hiện tại**. Bản sao các file Python bị thay được lưu vào `backups/`. Các lượt chạy và mã Java cũ được giữ nguyên.

## Chạy trên Ubuntu

Tải `sql_source_fix_v1.zip` vào Downloads rồi chạy:

```bash
cd ~/AI_sec_tool
unzip ~/Downloads/sql_source_fix_v1.zip -d .
python3 sql_source_fix_v1/install.py
python3 recheck_sql_source.py --check
```

Khi thấy `SOURCE_RECHECK_OK`, chạy:

```bash
OLLAMA_TIMEOUT=900 python3 recheck_sql_source.py --run
```

Chỉ cần Ollama với đúng bản Qwen2.5-Coder 14B đã dùng. Lượt này sử dụng cảnh báo, mã nguồn và kết quả phân tích SQL đã lưu, nên không cần khởi động SonarQube, Docker hoặc Joern. Nếu Ollama chưa chạy, mở terminal khác, chạy `ollama serve` và giữ terminal đó mở. Nếu cổng đã được sử dụng, không mở thêm server.

Cuối lượt sẽ có dòng **ZIP CẦN GỬI**. Gửi file ZIP ở đường dẫn đó để đối chiếu. Có thể mất nhiều phút cho mỗi lượt sinh trên máy hiện tại.

Mặc định script đọc lượt tám mẫu:
`runs/multi-owasp-holdout-20261115T151839Z-b04660-688bdde398e1`.
Nếu thư mục này đã chuyển vị trí, thêm `--previous-run ĐƯỜNG_DẪN_THƯ_MỤC` vào cả lệnh `--check` và `--run`. Thư mục phải có đủ artifact, không chỉ `ai_results.json`.

## Nội dung sửa

- Hướng dẫn kiểm tra nguồn nêu rõ đọc HTTP parameter, header, cookie và đối số main; phân biệt biến cục bộ với tham số phương thức và xem caller/helper ngay trong tệp.
- Kiểm tra dòng dẫn không vượt phạm vi, không trống/bình luận/ngoặc đơn thuần. Khẳng định nguồn phải dẫn vị trí SQL đang xét.
- Nếu JSON hoặc dòng dẫn không hợp lệ, cho mô hình sửa tối đa một lần và lưu cả hai đầu ra. Lỗi kết nối, cắt đầu ra hoặc đầy ngữ cảnh không tự gọi lại.
- Mỗi thông tin còn thiếu từ bước SQL được đối chiếu riêng. Chỉ mục về nguồn được mô hình báo cáo đã giải quyết, có bằng chứng phù hợp và EXTERNAL_READ, mới được bỏ khỏi danh sách thiếu cuối. Mục cũ và lý do giải quyết đều được lưu. Những thiếu sót về helper/tác động SQL vẫn được giữ.
- Tích hợp cùng logic vào nhánh SQL của pipeline. Nhánh Path/Command giữ nguyên. Một lượt SQL đầy đủ có tối đa bốn lần sinh; lượt chạy lại riêng nguồn này tối đa hai lần/mẫu, tức tối đa 16 lần cho tám mẫu.

## Phạm vi kết quả

Lượt này **tái sử dụng bước 1 và bước 2 đã lưu**, chỉ chạy lại kiểm tra nguồn trên cả tám mẫu. Nhận định tác động SQL, gồm lỗi suy luận nhánh `switch` đã phát hiện, chưa được sửa ở gói này. Các kết quả vẫn cần đối chiếu mã nguồn và nhãn tham chiếu sau khi chạy. Kiểm tra dòng và đối chiếu thiếu sót do mô hình thực hiện không phải chứng minh ngữ nghĩa.

Script không đọc nhãn tham chiếu OWASP. Đây là sửa lỗi sau khi xem kết quả đánh giá, không được báo cáo thành một bộ holdout mới độc lập hoặc một lượt đánh giá lại toàn bộ 49 cảnh báo. Không ghi đè nhãn AI hay nhãn thẩm định của lượt cũ.

## Chạy lại sau gián đoạn

Chạy lại cùng lệnh sẽ dùng các kết quả đã lưu, kể cả kết quả có lỗi. Nếu chương trình báo một lần gọi đã bắt đầu nhưng chưa lưu xong, dùng:

```bash
OLLAMA_TIMEOUT=900 python3 recheck_sql_source.py --run --retry-incomplete
```

Lệnh này cho phép gọi lại **lần chưa lưu**, vì không biết server đã sinh xong hay chưa. Nó không gọi lại các kết quả lỗi đã lưu. Khi có lỗi đã lưu, gửi ZIP để chẩn đoán trước khi mở một lượt thử khác.

Không chạy lại `recheck_sql_context.py` của gói trước: nó đóng băng hash backend cũ và sẽ từ chối cấu hình mới. Hai bước SQL được tái sử dụng trong lệnh mới nên không cần chạy lại gói cũ.

## Kiểm tra đã thực hiện trước khi đóng gói

Xem `verification.json`. Các ca gọi mô hình trong kiểm thử dùng đầu ra mô phỏng để kiểm tra xử lý lỗi, checkpoint, phép ghép và đóng ZIP. Chưa chạy Qwen thật trên bản cập nhật; chưa có số liệu tăng độ chính xác. `--check` được chạy với đúng tám artifact người dùng cung cấp.
