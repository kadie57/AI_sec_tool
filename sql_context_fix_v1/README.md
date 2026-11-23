# Bản sửa đầu tiên: giới hạn đầu vào SQL

Cài vào dự án `~/AI_sec_tool` hiện có. Không tạo bản sao dự án.

## Đã sửa gì?

Nhánh SQL của bộ định tuyến dùng Joern để kiểm tra luồng/vị trí sink, rồi
dựng lại các yêu cầu AI từ mã Java. Tuy nhiên, bộ kiểm tra kích thước cũ
cộng cả ký tự CPG không gửi cho AI. Trong lượt đã cung cấp, tám cảnh báo
có mã Java dài 2.736–4.186 ký tự bị chặn vì tổng Java + CPG vượt 10.000.

Bản sửa chỉ bỏ CPG khỏi phép tính sơ bộ khi nhánh SQL thực sự không gửi
CPG tới AI. Lệnh chạy `master_pipeline.py` trực tiếp vẫn tính CPG vì cách
đó có gửi CPG trong prompt. Giới hạn mã nguồn 10.000 ký tự và kiểm tra
`prompt_eval_count`, kết thúc sinh, định dạng và bằng chứng ở các bước AI
được giữ lại. Giới hạn ký tự không phải phép đếm token và không bảo đảm
mọi yêu cầu sẽ vừa ngữ cảnh 4.096 token; lần chạy mới vẫn có thể báo lỗi
ngữ cảnh hoặc UNKNOWN. Không cắt mã tự động, không ép nhãn TP/FP.

## Cài đặt

Giải nén để có `~/AI_sec_tool/sql_context_fix_v1/install.py`, rồi:

```bash
cd ~/AI_sec_tool
python3 sql_context_fix_v1/install.py
python3 recheck_sql_context.py --check
```

Installer chỉ chấp nhận hai file backend đúng hash đã kiểm tra hoặc đúng
bản cập nhật này. Nó sao lưu file cũ vào `backups/sql_context_fix_v1_...`
trước khi cập nhật. Nếu file máy bạn khác, dừng và gửi thông báo lỗi;
không xóa hoặc nới kiểm tra hash.

`--check` không gọi dịch vụ và không tạo lượt phân tích. Nó kiểm tra nguồn
theo lần quét, cấu hình, các dependency cũ và sự thay đổi đã công bố.

## Chạy lại riêng tám cảnh báo SQL

```bash
cd ~/AI_sec_tool
OLLAMA_TIMEOUT=900 python3 recheck_sql_context.py --run
```

Cần Docker daemon, image Joern đã dùng và Ollama/model cũ sẵn sàng.
Không cần bật SonarQube hoặc nhập token vì dùng lần thu thập đã lưu.
Tối đa 24 lượt sinh mới cho tám cảnh báo nếu tất cả đi qua đủ ba bước.
Chạy lại cùng lệnh sẽ dùng checkpoint của lượt sửa, kể cả lỗi đã lưu.
Nếu bị ngắt giữa một cảnh báo, script chỉ rõ trường hợp cần thêm
`--retry-incomplete`; tùy chọn này có thể lặp lại các bước AI của cảnh báo dở.

Mặc định đọc lượt:
`runs/multi-owasp-holdout-20261115T151839Z-b04660-f56d1218dcb6`.
Kết quả sửa được lưu thành lượt riêng trong `runs/` với hash cấu hình mới.
Cuối lệnh có dòng **ZIP CẦN GỬI**; gửi file đó để xem nhãn và lỗi thực tế.

## Cách hiểu kết quả

Đây là lần chạy sửa lỗi sau khi đã xem kết quả bộ OWASP, không phải một
holdout độc lập mới. Script chọn cảnh báo theo lỗi xử lý cũ, không đọc
`reference_labels.json`, không lựa chọn theo nhãn đúng/sai. Nó giữ cách
che chú thích Java của lượt trước, số dòng, mã gốc, model, prompt, options
và chính sách quyết định. Lượt ban đầu và kế hoạch đóng băng không bị sửa.
Không chạy lại `run_holdout_system.py` để giả vờ backend mới là backend cũ;
script đó có chủ đích kiểm tra đúng phiên bản đã đóng băng.

Sửa giới hạn chỉ giúp tám cảnh báo đi đến bước phân tích. Chưa có kết quả
AI mới ở máy người dùng, chưa chứng minh độ chính xác tăng. Các lỗi nguồn
HTTP, dạng lệnh, luồng Path và nhận định sai phải được xử lý riêng sau đó.

## Kiểm tra đã thực hiện khi đóng gói

Xem `verification.json` và `test_sql_context_fix.py`: kiểm tra hồi quy
offline, bao gồm tám artifact thật của lượt cũ và kết quả mô phỏng lời gọi
AI. Không chạy Ollama hoặc Joern trong quá trình kiểm tra này.

Bộ kiểm tra cấu hình SQL đầy đủ còn cần các hồ sơ baseline lịch sử trên máy
Ubuntu của bạn. Những hồ sơ đó không có đầy đủ trong ZIP mới gửi; vì vậy
phải chạy `--check` trên máy bạn trước khi gọi AI. Kiểm tra luồng điều khiển
offline có mô phỏng bước nạp hồ sơ này; chi tiết được ghi trong verification.json.
