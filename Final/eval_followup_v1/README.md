# Follow-up evaluation v1 — 12 mẫu Java

Đây là bộ mẫu tổng hợp mới sau phát triển, KHÔNG phải benchmark độc lập, không chứng minh chất lượng doanh nghiệp. Một số mẫu chia sẻ nguyên lý với mẫu cũ; đây là đánh giá biến thể và tổ hợp luồng, không phải 12 cơ chế hoàn toàn mới. Không huấn luyện/fine-tune.

## Cài đặt và chốt cấu hình

Giải nén để có `~/AI_sec_tool/eval_followup_v1/run_eval.py`.

```bash
cd ~/AI_sec_tool
python3 eval_followup_v1/run_eval.py init
```

Init gọi javac để biên dịch nhưng KHÔNG thực thi Java; sau đó thêm 12 file vào `Clean_Code/eval_followup21`. Từ chối ghi đè nội dung khác. Giữ nguyên 17 mẫu hiện có. Ghi hash các Python root, file công cụ đánh giá, manifest bộ mẫu, đáp án và mã Java vào freeze.json. Không sửa code/prompt/model trong lượt đánh giá. Freeze không khóa file hệ điều hành; các lệnh sau kiểm tra hash để phát hiện thay đổi. Model/Joern do router ghi nhận ở runtime; nếu đổi mô hình thì phải coi là một thí nghiệm khác.

## Quét SonarQube

```bash
SONAR_PROJECT_KEY=project_1 python3 master_pipeline.py --collect-only
```

Lệnh có quét lại toàn bộ Clean_Code (17 mẫu cũ + 12 mới) và cập nhật project_1 trên SonarQube; các run cũ trên đĩa không bị ghi đè. Cần SonarQube và DB hoạt động, token phù hợp. Không đưa token vào file gửi lại. Những dòng hỗ trợ=False ở collector SQL cũ không chứng minh router đa nhánh không hỗ trợ.

Ghi lại đường dẫn `Kết quả:` của lượt mới. Với đường dẫn đó:

```bash
python3 eval_followup_v1/run_eval.py inventory --collection runs/TEN_LUOT_THU_THAP_MOI
```

Gửi file inventory_*.txt được in ra và manifest.json của lượt thu thập. Mẫu không có cảnh báo đúng rule được ghi NO_ALERT: không coi là AI đúng, cũng không tự gọi AI bằng cảnh báo giả. Không bật/tắt rule giữa lượt chỉ để làm đẹp kết quả; nếu profile thiếu rule phải sửa cấu hình rồi ghi lượt quét mới riêng.

## Phân tích (sau khi xác nhận inventory)

```bash
OLLAMA_TIMEOUT=900 python3 eval_followup_v1/run_eval.py analyze --collection runs/TEN_LUOT_THU_THAP_MOI
```

Chỉ chọn component của bộ mẫu có cảnh báo đúng rule. Router hiện có được gọi nguyên trạng, check trước rồi phân tích, không đọc đáp án để tạo request. Các cảnh báo khác thuộc cùng component nhưng nằm trong rule router hỗ trợ vẫn có thể được phân tích; scorer chỉ ghép đúng rule kỳ vọng. Giới hạn tối đa theo số CẢNH BÁO, không theo số file; nếu mỗi file có một cảnh báo thì tối đa 28 lượt AI, thường ít hơn do NO_ALERT/gate. Checkpoint/timeout theo router; `--retry-incomplete` chỉ dùng nếu router báo có cảnh báo dở dang. Không tự thay đổi timeout/prompt để lấy kết quả đẹp trong cùng lượt.

## Đối chiếu kết quả

```bash
python3 eval_followup_v1/run_eval.py score --collection runs/TEN_LUOT_THU_THAP_MOI --result-run runs/TEN_LUOT_AI_MOI
```

Đáp án ở reference_labels.json là nhãn đề xuất của người xây bộ mẫu, cần thẩm định trước khi dùng như ground truth trong khóa luận. Scorer chỉ đọc đáp án sau khi phân tích. Không sửa nhãn theo dự đoán AI; nếu sửa lỗi đáp án phải lưu phiên bản và lý do, đánh giá lại minh bạch.

Ma trận nhầm lẫn ba trạng thái TP/FP/UNKNOWN được tách theo nhãn AI và nhãn kết hợp (có luật tĩnh). Lỗi/abstain được ghi NOT_ANALYZED, không đổi thành UNKNOWN ngữ nghĩa. NO_ALERT không nằm trong mẫu số triage. Mẫu boundary và scanner_control báo riêng; không trộn vào core. Nếu một file có nhiều cảnh báo thì đơn vị ma trận là cảnh báo, không phải file. Không tự gộp để tăng điểm. Lời giải thích và dòng bằng chứng cần đối chiếu riêng; score không đánh giá chất lượng lập luận.

## Phạm vi nhãn

- SQL: khả năng dữ liệu thay đổi cấu trúc truy vấn; không chứng minh tài khoản DB hoặc DB thật tồn tại.
- Path: traversal qua giá trị tên/đường dẫn trong mã. FP của chuyển kiểu không xác nhận quyền truy cập từng file, trạng thái symlink hay race. Đây là phạm vi nhãn tham chiếu; phải nêu khi so sánh với prompt CONFINED có thể thận trọng hơn. Nếu mô hình trả UNKNOWN vì filesystem, ghi nhận bất đồng phạm vi thay vì tùy ý sửa đáp án.
- Command: chương trình chuẩn GNU find trên Ubuntu và Runtime.exec(String). Tách đối số cho phép chèn thêm action khi đầu vào không giới hạn; không cần shell ngầm. Mẫu shell là boundary vì adapter hiện tại từ chối shell/wrapper. Không thực thi các mẫu để chấm điểm.
- UNKNOWN: thiếu caller/nguồn bên ngoài trong ngữ cảnh một file, không đồng nghĩa code an toàn.

Nguồn đối chiếu cơ chế GNU find: https://www.gnu.org/software/findutils/manual/html_node/find_html/Single-File.html và https://www.gnu.org/software/findutils/manual/html_node/find_html/find-Expressions.html .

## Kiểm tra đã thực hiện

- Đọc đủ 17 mẫu gốc và 3 module tích hợp gửi kèm.
- Kiểm tra cú pháp Python; kiểm thử inventory/scorer bằng dữ liệu giả lập gồm NO_ALERT, boundary abstain, đủ 9 mẫu core, phát hiện sửa nguồn sau freeze.
- Kiểm tra adapter Command thật nhận Sample301/302/303 và từ chối shell Sample304.
- Bản sửa compile-fix-1: bổ sung dấu đóng lớp cuối 12 file và cập nhật SHA-256. Đã biên dịch thành công cả 12 mẫu bằng OpenJDK 17 (jdk.compiler), không thực thi mẫu. Đã kiểm tra init hai lần trên thư mục tạm. Chưa chạy SonarQube, Joern hoặc Ollama; không coi kiểm thử công cụ là kết quả đánh giá AI.
