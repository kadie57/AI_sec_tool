# AI đề xuất bản sửa lỗi · v1

Gói cập nhật cho giao diện đã cài `ui_priority_v1`. Tạo bản nháp sửa một file Java bằng Ollama đang chạy trên máy, hiển thị so sánh trước–sau, giải thích, giả định và kế hoạch kiểm thử; cho tải mã Java, unified diff `.patch` và JSON đề xuất.

## Phạm vi

- SQL Injection JDBC, Path Traversal đọc tệp và Command Injection theo các rule đã hỗ trợ.
- Chỉ tạo bản sửa khi người thẩm định đã lưu **LIKELY_TP** cho đúng bản ghi/mã nguồn và lượt phân tích đã hoàn tất.
- File trong `Clean_Code` phải khớp hash mã nguồn của lượt quét. Khi đã sửa file, quét và thẩm định lại trước khi tạo đề xuất mới.
- Bản đầu hỗ trợ tối đa 200 dòng và 12 KB cho một file. Không sửa nhiều file, caller chưa được cung cấp hoặc cấu hình ngoài mã nguồn.
- Mỗi yêu cầu mới gọi AI sinh nội dung tối đa một lần. GET/xem/tải trang không gọi AI. Yêu cầu đã có bản đề xuất hợp lệ được dùng lại; lỗi có thể thử lại bằng nút.
- Bản sửa được lưu riêng dưới `.review_jobs/<mã tác vụ>/`. **Không tự ghi đè Java, không tự áp dụng patch, không biên dịch/chạy mã AI, không đổi nhãn gốc hoặc đóng cảnh báo SonarQube.**
- Kiểm tra JSON, token, hash và nguồn thẩm định chỉ bảo đảm tính nhất quán của dữ liệu. Chúng không chứng minh bản sửa đúng hoặc an toàn.

## Cài đặt

1. Chờ các tác vụ trên UI hoàn tất, rồi Ctrl+C ở terminal đang chạy Flask.
2. Giải nén vào `~/AI_sec_tool` để có `~/AI_sec_tool/ui_patch_v1/install.py`.
3. Kiểm tra:

```bash
cd ~/AI_sec_tool
source .venv_review_ui/bin/activate
python ui_patch_v1/install.py --check
```

Chỉ tiếp tục khi có `INSTALL_CHECK_OK`:

```bash
python ui_patch_v1/install.py
ollama list
python review_ui/app.py
```

Không cần thư viện Python mới ngoài môi trường UI hiện có. Gói dùng thư viện chuẩn Python để gọi Ollama. Trình cài đối chiếu hash và sao lưu dưới `backups/ui_patch_<thời điểm>`. Gói cập nhật UI và worker của UI; không thay đổi các file pipeline, prompt kiểm chứng hoặc dữ liệu thực nghiệm cũ.

Nếu `--check` báo file khác bản: gửi nguyên thông báo để đối chiếu. Không bỏ qua kiểm tra hoặc sửa hash bằng tay. Không cần khởi động SonarQube/Joern cho thao tác tạo đề xuất từ kết quả có sẵn này.

## Thử lượt đầu tiên

1. Mở `http://127.0.0.1:5050` và chọn lượt ba cảnh báo đã thẩm định.
2. Vào **Ưu tiên xử lý** → ở **PathCase01.java**, bấm **Đề xuất sửa lỗi**. Cũng có thể mở từ trang bằng chứng sau phần thẩm định.
3. Bấm **Yêu cầu AI đề xuất bản sửa**. Trang tự tải lại mỗi 5 giây. Có thể đóng tab/Flask rồi mở lại; giữ máy hoạt động vì tắt máy sẽ ngắt tác vụ.
4. Khi có bản nháp, đọc giải thích, phần mã thêm/bớt, giả định và kế hoạch kiểm thử.
5. Tải **toàn bộ đề xuất JSON** và gửi lại để đối chiếu. Chưa thay file mẫu gốc ở bước này: cần kiểm tra xem bản sửa giữ đúng chức năng và xử lý nguyên nhân cảnh báo trước.

Nếu AI trả `NEEDS_CONTEXT`, trang sẽ nêu thông tin cần bổ sung. Nếu lỗi/kết quả bị cắt, mở nhật ký. Hệ thống không tự thử lại. Tác vụ dùng chung khóa với quét/phân tích UI nên không khởi chạy đồng thời các tác vụ nặng từ giao diện.

Thử lại sau lỗi dùng tối đa một lượt mới. Bấm lại khi đã có kết quả thành công và dữ liệu không đổi sẽ mở bản đã lưu. Muốn thay ngữ cảnh thực nghiệm, bổ sung dữ liệu đúng quy trình rồi thẩm định lại; không sửa nhãn chỉ để buộc AI gọi lại.

## Cấu hình mặc định

- Mô hình: `qwen2.5-coder:14b-instruct-q4_K_M` (có thể đặt `PATCH_MODEL` trước khi mở UI).
- URL: `http://127.0.0.1:11434`; chỉ dùng Ollama cục bộ. Không tự tải mô hình.
- `num_ctx=8192`, `num_predict=3072`, `temperature=0`, `seed=42`.
- Timeout sinh: `PATCH_TIMEOUT`, nếu chưa đặt dùng `OLLAMA_TIMEOUT`, mặc định 900 giây; từ 30 đến 3600 giây. Thời gian toàn tác vụ được chặn ở timeout + 20 giây cho các bước kiểm tra.
- Ngữ cảnh 8192 có thể cần nhiều RAM hơn lượt kiểm chứng dùng 4096. Nếu máy báo lỗi bộ nhớ, gửi nhật ký để chọn cấu hình phù hợp; chưa thay mô hình hoặc thông số kiểm chứng cũ.

Ví dụ tăng thời gian chờ cho lượt tạo bản sửa trước khi khởi động UI:

```bash
PATCH_TIMEOUT=1800 python review_ui/app.py
```

Thời gian thực tế tùy máy và độ dài bản sửa. `PATCH_MODEL` chỉ ảnh hưởng chức năng đề xuất sửa lỗi; không phải fine-tune và không đổi cấu hình pipeline kiểm chứng.

## Dữ liệu lưu theo tác vụ

- `job.json`: trạng thái, tham chiếu cảnh báo, cấu hình, digest mô hình, hash yêu cầu/kết quả, thời gian.
- `source.java.txt`: bản nguồn dùng để đề xuất.
- `request.json`: yêu cầu sinh bản sửa.
- `ollama_response.json`: phản hồi đầy đủ nếu đã nhận được, kể cả trường hợp kiểm tra tiếp theo thất bại.
- `proposal.json`: kết quả có cấu trúc và diff nếu đủ điều kiện lưu để xem xét.
- `output.log`: nhật ký ngắn; không in token hay toàn bộ source ra log.

Nếu nguồn hoặc thẩm định đổi sau khi có đề xuất, vẫn xem lại lịch sử nhưng khóa tải bản sửa cũ. Chức năng không tự ghi nhận “đã sửa”; muốn chứng minh hiệu quả cần áp dụng trên bản sao/nhánh riêng, kiểm thử hành vi và quét lại.

## Kiểm thử đã thực hiện

```bash
python ui_patch_v1/test_patch.py
```

Bộ kiểm tra sử dụng HTTP server Ollama giả lập và worker thật trong thư mục tạm. Không gọi mô hình hoặc SonarQube của bạn. Bao gồm lưu/tải bản sửa, nguồn/hash/thẩm định, bấm lặp, khóa tác vụ, thay thẩm định trong lúc chạy, JSON cắt ngắn, NEEDS_CONTEXT, XSS, CSRF, bản đề xuất bị thay đổi và các trang UI hiện có.

Các kiểm tra này kiểm chứng phần tích hợp, chưa đo chất lượng bản sửa do Qwen sinh. Lượt PathCase01 trên máy bạn là lần thử mô hình thật cho tính năng này.

## Tài liệu định hướng cho prompt

- Ollama Generate API: https://docs.ollama.com/api/generate
- SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OS Command Injection Defense: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- Java Path API (resolve, startsWith, toRealPath): https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Path.html

Prompt áp dụng các nguyên tắc này theo loại cảnh báo. Mô hình vẫn có thể đề xuất sai hoặc đổi hành vi ngoài ý muốn; cần đối chiếu mã và kiểm thử độc lập. Không coi việc cảnh báo biến mất sau quét lại là bằng chứng duy nhất rằng lỗi đã được sửa.
