# Cập nhật Path v7: bằng chứng điều kiện từ mã Java

## Kết quả v6 vừa nhận

Tệp `path_context_review(2).zip` chạy đúng `path22-file-read-v6-value-flow`, cùng hash nguồn, model digest và cấu hình generation với lượt v5. Bốn lời gọi AI hoàn tất, không bị cắt đầu ra. Lượt v6 mất khoảng 14 phút 34 giây tính cả xử lý.

| Mẫu phát triển | v5 | v6 | Đối chiếu code và nhãn OWASP |
|---|---|---|---|
| BenchmarkTest00001 | UNKNOWN | LIKELY_TP | Đã nhận ra cookie request đi qua ghép đường dẫn tới mở/đọc file, phù hợp nhãn true |
| BenchmarkTest00063 | UNKNOWN | UNKNOWN | AI vẫn đọc sai nhánh hằng và gọi biến cục bộ là tham số; nhãn tham chiếu false |

Ở mẫu 00063, dòng 69 gán num=106; dòng 71 tính (7*18)+num > 200, tức 232 > 200. Nhánh được chọn là chuỗi cố định. Dòng 77 ghép bar vào đường dẫn và dòng 78 mở file. Kết quả UNKNOWN là kết quả AI thực tế, không đổi thành FP để làm đẹp số liệu. Trong lời giải thích đường dẫn v6, dòng 79 là khai báo bộ đệm; dòng đọc file thực tế là 80.

Đây là hai mẫu phát triển đã xem và dùng để điều chỉnh hệ thống, không phải bộ kiểm tra độc lập và không dùng để công bố độ chính xác tổng quát.

## v7 thay đổi gì, vì sao

Bổ sung bộ đọc AST Java dựa trên javac, tính một phạm vi hẹp các biểu thức int/boolean cục bộ và ghi lại nhánh của toán tử ?: khi xác định được. Số học int thực hiện bằng Java, gồm tràn số, phép chia số âm và từ chối chia cho 0. Khi gặp ghi đè không xác định, if/loop/try/switch chưa xử lý, các biến bị ghi sẽ mất trạng thái hằng; không đoán nhánh.

Bằng chứng được thêm vào yêu cầu AI, kèm số dòng phụ thuộc. AI vẫn phải theo giá trị được chọn tới đúng thao tác file và xét ghi đè/nguồn khác. Bộ tính không xác minh toàn bộ luồng dữ liệu, không tự kết luận TP/FP và không tự xác nhận an toàn filesystem. Không thực thi chương trình đầu vào; chỉ parse mã. JDK 17+ phải có compiler module (máy đã dùng JDK 21 phù hợp).

Giữ nguyên so với v6: system prompt, schema, ánh xạ verdict, mô hình, options, toàn bộ source/số dòng, truy vấn Joern, các bộ kiểm tra tĩnh đã có. Chỉ thêm bằng chứng điều kiện và hướng dẫn sử dụng bằng chứng vào user prompt khi tìm được nhánh. Với 00001 không tìm được nhánh trong phạm vi bộ tính, request vẫn giống v6. Với 00063 bộ tính ghi nhận đúng dòng 71, phụ thuộc dòng 69, vế trái 232, vế phải 200, chọn nhánh true. Đây là kết quả phân tích tĩnh đã kiểm tra, chưa phải phản hồi Qwen v7.

Không có tên mẫu/nhãn OWASP, số dòng đáp án hay giá trị riêng của mẫu được hard-code trong bộ tính hoặc prompt. Các ghi chú đánh giá trong gói chỉ phục vụ người đọc, không được chương trình AI nạp.

## Cài lên dự án hiện có

1. Tải lại ZIP mới nhất, giải nén vào `~/AI_sec_tool`, chọn thay thế thư mục `owasp_path_context_fix`.
2. Khi không có lượt Path đang chạy:

```bash
cd ~/AI_sec_tool
python3 owasp_path_context_fix/install.py --check
```

Phải hiện `PATCH_CHECK_OK: v7-branch-evidence`. Lệnh này cũng kiểm tra JDK/bộ tính bằng một đoạn mã tổng hợp; không gọi AI/SonarQube/Joern.

3. Cài:

```bash
python3 owasp_path_context_fix/install.py --apply
```

Cập nhật `path_triage_v2.py` và thêm hai tệp hỗ trợ `path_branch_evidence_v1.py`, `PathBranchEvidence.java`. Installer giữ v6 trong `backups/path_context_v7/`, từ chối ghi đè file đã sửa khác bản đã đối chiếu.

4. Chạy lại hai mẫu Path từ lượt SonarQube đã có:

```bash
OLLAMA_TIMEOUT=900 python3 path_triage_v2.py \
  --from-run runs/owasp-compat-20261114T045846Z-8508c7
```

Cần Docker/Joern và Ollama hoạt động. Tối đa 4 lời gọi AI. Không cần token hoặc quét SonarQube mới. Lượt v6 được giữ nguyên; v7 có thư mục kết quả riêng theo cấu hình. Gửi ZIP đúng đường dẫn sau dòng `GÓI CHẨN ĐOÁN CẦN GỬI`. ZIP mới có thêm `branch_evidence.json` cho từng cảnh báo.

Nếu cần quay lại v6:

```bash
python3 owasp_path_context_fix/install.py --restore
```

## Xác minh trước khi giao

9 kiểm thử tự động đã đạt, gồm 21 biến thể biểu thức/phép gán trong bộ thử: nhánh true/false, nhánh chọn input, tràn int, chia số âm, ghi đè, nguồn chưa biết, if/loop/try, compound assignment, tăng biến, kiểu long ngoài phạm vi, chia 0, field/parameter chưa biết, scope giữa các hàm, và ký tự tiếng Việt. Kiểm tra ghép dùng mã các bộ kiểm tra tĩnh lấy từ bản dự án đã tải lên ngày 28/10; phản hồi AI và Joern được mô phỏng, không giả vờ có suy luận thực tế.

Đã kiểm tra: source/options/schema/system không đổi; không tự đổi nhãn khi có bằng chứng; từ chối bằng chứng khác hash nguồn; cài, cài lặp, khôi phục và từ chối file đã sửa. Hash các helper và Java runtime được ghi trong context của lượt standalone.

Giới hạn: không type-check đầu vào, chỉ dùng các biểu thức primitive hỗ trợ; không phân tích trường đối tượng, hàm bên ngoài hoặc toàn bộ điều khiển Java. Một điều kiện được tính đúng không tự chứng minh toàn bộ cảnh báo là FP. Cần tiếp tục đối chiếu kết quả v7, sau đó xử lý hỗ trợ ProcessBuilder và ngữ cảnh helper trước khi đóng cấu hình cho bộ kiểm tra độc lập.

Tham khảo ngữ nghĩa Java: [JLS: Integer Operations](https://docs.oracle.com/javase/specs/jls/se17/html/jls-4.html#jls-4.2.2), [JLS: Conditional Operator](https://docs.oracle.com/javase/specs/jls/se17/html/jls-15.html#jls-15.25).
