# Bổ sung ngữ cảnh helper và phân tích lại SQL

Gói này bổ sung ba mô-đun vào dự án AI_sec_tool hiện tại. Đây là nhánh phân tích
lại tám cảnh báo SQL đã chọn ở lượt trước; chưa thay tuyến chạy mặc định của
master_pipeline_multi_v1.py. Cần đối chiếu kết quả Qwen mới trước khi đưa nhánh
này vào pipeline chung. Không tạo lại ứng dụng/giao diện.

## Thay đổi

1. Đọc mã chính và helper tại **đúng Git commit của lượt SonarQube đã lưu**, kiểm
   tra hash mã chính trước khi ghép. Xét khai báo đối tượng, constructor, lời gọi
   factory trên đường giá trị và một dạng reflection dựa trên `.properties`.
   Cung cấp cả lớp được cấu hình và các lớp fallback thấy trong code.
2. Gọi Qwen mới hai bước riêng: nguồn/giá trị thực sự tới SQL, rồi tác động lên
   cú pháp SQL. Hai bước đọc cùng bộ code, không đọc đáp án của nhau hay kết luận
   cũ. Bước SQL được tính lại, không kế thừa `sql_effect` cũ.
3. Yêu cầu xét gán lại, điều kiện hằng, chỉ số `charAt`, nhánh `switch`, giá trị
   trả về, vị trí ghép SQL và vị trí bind. Đây là hướng dẫn suy luận chung,
   không gán đáp án theo tên mẫu.
4. Dẫn chứng có mã tệp và dòng, ví dụ `F0:43`, `F1:36`. Python tra lại dòng từ
   source gốc. Dòng trắng/comment không được chọn; chữ ký hàm không đủ làm bằng
   chứng đọc bên ngoài. Có kiểm tra điểm đọc API tối thiểu, chưa chứng minh ngữ nghĩa.
5. Không bỏ khoảng trống helper vì đã thấy HTTP. Nếu hai bước mâu thuẫn về giá trị
   cố định và khả năng thay đổi cú pháp, kết quả ghép là UNKNOWN.

## Cài vào dự án cũ

Giải nén để có thư mục `~/AI_sec_tool/sql_context_review_v1`, sau đó:

```bash
cd ~/AI_sec_tool
python3 sql_context_review_v1/install.py --project .
python3 recheck_sql_context.py --check
```

Chỉ tiếp tục khi thấy `INSTALL_OK` và `SQL_CONTEXT_CHECK_OK: 8 cảnh báo`.
Installer kiểm tra mọi dependency trước khi ghi, lưu manifest vào backups,
ghi nguyên tử và không ghi đè file tự chỉnh sửa. Gói yêu cầu bản merge guard
đã cài ở lượt trước.

Repo mặc định là `~/AI_sec_benchmarks/BenchmarkJava`, tức bản đã clone trước đó.
Nếu repo ở chỗ khác, thêm `--repository /duong/dan/BenchmarkJava` vào cả lệnh
`--check` và `--run`. Đọc Git tại commit đã quét, không dùng sửa đổi trong worktree.
Không tải repo qua mạng và không chạy chương trình Java trong benchmark.

## Chạy Qwen

```bash
cd ~/AI_sec_tool
ollama list
OLLAMA_TIMEOUT=900 python3 recheck_sql_context.py --run
```

Lượt này dùng cảnh báo SonarQube đã lưu. Chỉ cần dịch vụ Ollama và mô hình
`qwen2.5-coder:14b-instruct-q4_K_M` đúng digest cũ; không cần quét SonarQube hay
chạy Joern. `ollama list` chỉ kiểm tra kết nối. Nếu báo không kết nối được,
khởi động dịch vụ Ollama theo cách đã dùng trên máy rồi chạy lại.

Thông thường có **16 lượt sinh** (2 × 8). Mỗi bước chỉ được sửa lỗi JSON/dẫn
chứng tối đa một lần, nên tối đa 32 lượt sinh cho lần chạy không bị gián đoạn.
Context tăng từ 4096 lên 8192, `num_predict=1536`; mô hình, digest, nhiệt độ 0
và seed 42 giữ nguyên. Bản này thay cả ngữ cảnh và prompt/cấu hình suy luận;
không được quy mọi cải thiện cho riêng một yếu tố.

Cuối lệnh sẽ in:

```text
KẾT QUẢ: .../experiments/sql_context_recheck_v1/...
ZIP CẦN GỬI: ...-review.zip
```

Gửi đúng ZIP ở dòng `ZIP CẦN GỬI`. ZIP gồm code/helper đã dùng, hash, yêu cầu
gửi mô hình, phản hồi nguyên bản, các lần sửa, kết quả cũ để đối chiếu và tổng hợp.
Không cần tự tìm hay tự nén thêm. Các file kết quả cũ và nhãn người thẩm định
không bị ghi đè. Kết quả mới có trạng thái chờ thẩm định, chưa tự đóng cảnh báo.

## Khi bị ngắt

Chạy lại cùng lệnh sẽ dùng checkpoint, kể cả lỗi đã lưu; không tự gọi lại một lỗi
đã có phản hồi. Nếu tiến trình bị tắt giữa lúc đang sinh và thông báo có lượt
`STARTED` dở dang, cho phép thử lại riêng lượt chưa lưu bằng:

```bash
OLLAMA_TIMEOUT=900 python3 recheck_sql_context.py --run --retry-incomplete
```

Khi bị gián đoạn giữa lúc sinh, không thể khẳng định server chưa thực hiện lượt
cũ. Vì vậy số lượt thực tế có thể tăng nếu người dùng chọn thử lại. Lỗi kết nối
đã lưu kết thúc cảnh báo đó bằng UNKNOWN; chạy lại tiếp tục các cảnh báo khác.
Không xóa checkpoint lỗi để làm kết quả có vẻ tốt hơn; gửi ZIP để đối chiếu.

## Kiểm tra đã thực hiện trước khi giao

- 20 kiểm tra offline: truy nguyên đúng commit, helper/config/fallback, không
  đọc nhãn benchmark, che comment, bằng chứng sai dòng/tệp/chữ ký hàm, ghép có
  mâu thuẫn, giữ thông tin thiếu, giới hạn context, checkpoint và sửa một lần.
- Kiểm tra dữ liệu thật đã lưu của cả tám cảnh báo: nguồn khớp lượt thu thập;
  lấy được một helper cho wrapper HTTP, năm file hỗ trợ cho mỗi ca factory.
- Thử luồng xử lý đủ tám cảnh báo bằng phản hồi **mô phỏng UNKNOWN**: 16 lượt
  mô phỏng, chạy lại không sinh thêm, tạo ZIP, giữ nguyên dữ liệu đầu vào.
- Chưa chạy Qwen thật trên máy người dùng. Các kiểm tra phần mềm trên không
  phải số liệu độ chính xác của AI và không có kết quả benchmark mới trong gói.

Chạy lại kiểm tra offline sau khi cài, nếu cần:

```bash
python3 -m unittest discover -s sql_context_review_v1/tests -v
```

## Phạm vi kết luận

Đây là sửa lỗi sau khi đã xem các ca đánh giá, không còn là một tập holdout mới.
Không đọc nhãn tham chiếu trong analyzer, không đưa chúng vào prompt và không
ấn định trước số TP/FP. Các số liệu tám ca này không đại diện cho toàn bộ 49
cảnh báo được hỗ trợ hoặc mọi lỗi Java.

Việc bổ sung helper là kiểm kê ngữ cảnh có giới hạn, không phải phân tích liên
thủ tục đầy đủ của Java/Joern. Một dạng reflection có cấu hình được hỗ trợ;
override classpath khi triển khai và dispatch tổng quát chưa được mô hình hóa.
Các helper tạo kết nối/in kết quả JDBC không được mở rộng ở nhánh này. Không
tuyên bố CPG của helper đã được gửi tới LLM. Bằng chứng tra đúng dòng chưa tự
chứng minh rằng suy luận của mô hình là đúng.
