# Bổ sung ProcessBuilder vào backend Command Injection hiện có

Bản cài: `command78-direct-plus-processbuilder-v4-bounded-repair`.
Nhánh ProcessBuilder hiện tại: `command78-processbuilder-context-v3-bounded-repair`.

## Lượt tiếp theo: chỉ tiếp tục mẫu chưa hoàn tất

Lượt v2 đã xử lý được BenchmarkTest00006. BenchmarkTest00051 nhận ra giá trị lệnh cố định nhưng bỏ trống helper_evidence, nên chưa qua bước kiểm tra nguồn và chưa chạy bước tác động lệnh.

Bản này bổ sung một cơ chế chung: chỉ khi phản hồi đã sinh xong, parse được JSON và bị validator từ chối, cho mô hình đối chiếu lại một lần với mã gốc + phản hồi lỗi. Không tự sửa nhãn hoặc điền số dòng hộ AI. Mô hình có thể thay đổi nhận định, kể cả chuyển sang UNRESOLVED nếu không chứng minh được. Giữ nguyên câu trả lời đầu và câu sửa thành hai file riêng. Một lần sửa vẫn sai thì dừng; không lặp đến khi ra nhãn mong muốn.

Cài vào dự án hiện có:

```bash
cd ~/AI_sec_tool
python3 command_processbuilder_update_v1/install.py
python3 resume_command_processbuilder.py \
  --from-run runs/owasp-compat-20261114T045846Z-8508c7-command78-596247b366e3 \
  --check
```

Khi hiện REPAIR_CHECK_OK, chạy:

```bash
OLLAMA_TIMEOUT=900 python3 resume_command_processbuilder.py \
  --from-run runs/owasp-compat-20261114T045846Z-8508c7-command78-596247b366e3
```

Chỉ cần Ollama có cùng model/digest. Dùng nguồn, helper và CPG đã lưu; không gọi SonarQube, không chạy Joern/Docker, không cần token. Lượt này gọi AI tối đa 3 lần mới: sửa bước nguồn 1 lần, bước tác động 1 lần, và thêm 1 lần sửa tác động nếu JSON bước đó không hợp lệ. Những attempt đã ghi sẽ được dùng lại khi tiếp tục. Nếu ngắt đúng khi model đang sinh, phần chưa ghi có thể phải gọi lại.

BenchmarkTest00006 được giữ nguyên kết quả và prompt_version v2, đánh dấu REUSED_VALID_RESULT. Không đếm nó là dự đoán mới. BenchmarkTest00051 được ghi mode VALIDATION_REPAIR, giữ phản hồi đầu từ lượt trước, ghi riêng llm_source_repair.json và các phản hồi mới. File manifest ghi số API generation mới, provenance và phạm vi reuse. Thời gian trong hàng được kế thừa có nguồn từ lượt cũ; thời gian bước sửa gồm cả attempt đầu đã tái sử dụng, không phải toàn bộ đều là chi phí mới.

Gửi ZIP tại dòng ZIP CẦN GỬI. Lượt cũ không bị ghi đè. Chưa có kết quả Qwen thực tế với cơ chế sửa này.

Các yêu cầu nền, schema, model, options, mã nguồn/helper, validator và phép quyết định giữ nguyên so với v2. Phần mới là yêu cầu phản hồi lỗi có giới hạn và chương trình chạy tiếp. Đây là thay đổi cơ chế thử lại, cần ghi rõ khi so sánh thời gian và chất lượng. Không coi là thí nghiệm chỉ thay câu prompt nguồn.

Trong lượt phân tích mới từ đầu, mỗi cảnh báo ProcessBuilder có tối đa 4 generation (2 bước, tối đa 1 sửa/bước). Runtime cũ giữ tối đa 2. Router hiện có đã cập nhật cách in giới hạn lượt gọi.

## Cập nhật ngày 15/11/2026: sửa lỗi ở bước nguồn

Nhật ký thực tế cho thấy hai câu trả lời đã sinh xong, không bị cắt token. Mẫu thứ nhất nhận ra nguồn ngoài nhưng ghi thiếu bảo vệ vào missing_context; mẫu thứ hai chọn FIXED_VALUE nhưng giải thích mâu thuẫn, ghi bằng chứng đã có vào missing_context và trả file_id không khớp.

Bản này tách hướng dẫn bước nguồn khỏi hướng dẫn đánh giá tác động lệnh, yêu cầu giải thích nhất quán và định nghĩa rõ missing_context. Schema của mỗi yêu cầu chỉ cho chọn đúng file_id helper đang có; không có helper thì mảng tham chiếu phải rỗng. Câu trả lời đã parse được giữ riêng kể cả khi bị từ chối để dễ chẩn đoán.

Giữ nguyên model, tùy chọn sinh, mã đầu vào/helper, CPG, phép quyết định và các điều kiện kiểm tra cũ. Không tự xóa missing_context, sửa nhãn hoặc gán kết quả theo tên mẫu. Hai câu trả lời lỗi cũ vẫn bị từ chối. Chưa có kết quả Qwen thực tế với hướng dẫn mới.

Tải lại bản ZIP này, thay thư mục bản vá đã giải nén, rồi chạy install.py như dưới. Trình cài chấp nhận bản gốc và các bản ProcessBuilder v1/v2 đã gửi; chỉ file cần đổi mới được thay và sao lưu. Khi chạy lại cùng lệnh, hash module/prompt mới tạo thư mục kết quả mới nên không lấy lại hai checkpoint lỗi. Backend vẫn thuộc project hiện có.

## Mục đích

Nhận thêm cảnh báo tại `ProcessBuilder.command(List)` và constructor `ProcessBuilder(String[])`, nối với `start()` trên cùng biến local. Đây là bước mở rộng phạm vi và ngữ cảnh, không huấn luyện mô hình. Không chỉ đổi tên phiên bản hay gán nhãn theo tên mẫu.

Một constructor hoặc `command()` chỉ cấu hình; `start()` mới tạo tiến trình. Việc có shell phải xét danh sách chương trình/đối số thực tế. Không coi mọi `ProcessBuilder` là shell và không coi mảng đối số là bảo đảm an toàn.

## Cài vào project đang dùng

Giải nén ZIP này vào `~/AI_sec_tool`. Chạy từ thư mục dự án:

```bash
cd ~/AI_sec_tool
python3 command_processbuilder_update_v1/install.py
python3 command_triage_v2.py --from-run runs/owasp-compat-20261114T045846Z-8508c7 --check
```

Trình cài đối chiếu hash hai file hiện có trước khi thay, tự sao lưu vào `backups/command_processbuilder_<thời gian>/`. Nếu file đang dùng khác bản đã nhận, trình cài dừng trước khi sửa. Không ghi đè SQL, Path, mã Java hoặc kết quả cũ.

`--check` cần thấy hai API form `COMMAND_LIST` và `CONSTRUCTOR_STRING_ARRAY`, helper lần lượt 0 và 1, gaps đều `[]`. Chưa gọi AI/Docker/SonarQube.

Chạy tiếp:

```bash
OLLAMA_TIMEOUT=900 python3 command_triage_v2.py --from-run runs/owasp-compat-20261114T045846Z-8508c7
```

Cần Docker/Joern và Ollama có model Qwen14B. Dùng cảnh báo Sonar đã lưu; không quét lại, không cần nhập token. Với lượt đã chỉ ra: hai cảnh báo Command, tối đa tám yêu cầu sinh của AI nếu chạy cả hai mẫu từ đầu. Hai bước là kiểm tra nguồn và tác động lệnh, mỗi bước có thể sửa một lần. Có chạy Joern để lưu bằng chứng mới. Chạy lại cùng lệnh sẽ dùng checkpoint, kể cả lỗi đã lưu.

Kết thúc, gửi ZIP ở dòng **ZIP CẦN GỬI**; tên file là `command_processbuilder_results.zip`. ZIP gồm kết quả, phiên bản, yêu cầu/đáp ứng AI, nguồn, helper và bằng chứng Joern.

Nếu BenchmarkJava ở vị trí khác, đặt `OWASP_BENCHMARK_ROOT` trỏ tới repository. Mặc định: `~/AI_sec_benchmarks/BenchmarkJava`. Helper được đọc bằng `git show` tại `benchmark_commit` của lượt Sonar, không dùng tùy tiện file đang chỉnh sửa. Caller phải khớp bản tại commit đó.

## Những file được cập nhật

- `command_triage_v2.py`: giữ nguyên các hàm xử lý Runtime.exec cũ; chuyển các cảnh báo ProcessBuilder sang nhánh bổ sung; lưu ZIP kết quả.
- `command_processbuilder_v1.py`: nhận diện API hẹp, đối chiếu CPG, lấy helper một cấp có phiên bản, gọi hai bước AI, kiểm tra cấu trúc và ghép kết luận.
- `master_pipeline_multi_v1.py`: nạp ngữ cảnh Command trước khi tính fingerprint của lượt chạy; nhánh mới dùng được qua router hiện có. Nếu UI đã import module trong tiến trình cũ, khởi động lại UI trước khi tạo lượt mới.

Đây là bản vá backend của project hiện có. Mỗi lượt thực nghiệm vẫn tạo thư mục kết quả riêng để so sánh và không ghi đè bằng chứng cũ.

## Cách xử lý và giới hạn

- Nhận builder local với một cấu hình, một `start()`, không alias hoặc thêm lần dùng builder; chưa hỗ trợ fluent chain, nhiều `start`, các overload khác. Không tuyên bố hỗ trợ mọi cách dùng ProcessBuilder.
- Bộ nhận dạng cú pháp không chứng minh khả năng khai thác hay tính khả thi của đường đi. Nó được đối chiếu descriptor API từ Sonar và receiver/argument từ Joern.
- CPG vẫn trong một file. Helper một cấp được đưa riêng cho AI với số dòng và hash; đây chưa phải phân tích CPG liên thủ tục đầy đủ.
- Không hardcode `getTheValue` hoặc tên test để gán nhãn. Không đọc expectedresults CSV. Nguồn helper được phát hiện từ kiểu biến local khai báo rõ và khởi tạo trước cảnh báo. Kiểu suy luận, factory, helper tĩnh/lồng nhiều cấp chưa tự thu thập.
- Nhánh ProcessBuilder dùng `num_ctx=8192`, `num_predict=1536`, temperature 0, seed 42. Nhánh Runtime cũ giữ cấu hình 4096/1024. Đây là thay đổi cả phạm vi, ngữ cảnh, prompt và policy cho API mới, không phải phép so sánh riêng tác dụng của một câu prompt.
- Gửi CPG rút gọn (node cấu hình/start và số luồng) cho AI; lưu toàn bộ đường truyền trên đĩa. Luồng qua tham số không chứng minh đầu vào bên ngoài. Không có luồng không tự chứng minh an toàn.
- `FIXED_VALUE` + `INPUT_INDEPENDENT` nhất quán ở hai bước mới cho đề xuất LIKELY_FP theo tiêu chí không phụ thuộc đầu vào. Có helper mà thiếu trích dẫn helper thì kết quả không hợp lệ. Thiếu ngữ cảnh hoặc mâu thuẫn thì UNKNOWN.
- Trích dẫn hợp lệ chỉ chứng minh dòng tồn tại, chưa chứng minh lập luận AI đúng. Tất cả kết quả vẫn cần thẩm định; không tự đóng cảnh báo SonarQube.
- Đây vẫn là hai mẫu phát triển đã xem. Sau khi kiểm tra hoạt động, đóng phiên bản và đánh giá trên các mẫu chưa dùng chỉnh sửa, có nhãn tham chiếu xác lập trước. Không dùng hai mẫu này để tuyên bố độ chính xác tổng quát.

## Đã kiểm tra trước khi gửi

16 ca hồi quy offline ban đầu: hai dạng API trên log Joern thực tế; receiver/alias/multiple-start/config sai; thiếu flow; flow bằng 0; helper đúng commit; caller khác phiên bản; thiếu context; mâu thuẫn facts; dòng bằng chứng; checkpoint; các hàm Runtime cũ không đổi.

Kiểm tra CLI và trình cài: cài/sao lưu, chạy lại không cài thừa, từ chối file có sửa riêng, --check trên hai nguồn, tạo kết quả/ZIP và tiếp tục checkpoint. Kiểm thử đường gọi AI dùng đáp ứng mô phỏng, không phải kết quả đo độ chính xác Qwen. Chưa chạy Qwen hoặc Docker/Joern trực tiếp trong môi trường soạn bản vá; phần giải mã/đối chiếu CPG dùng log do máy Khanh đã tạo.

Tài liệu API đối chiếu: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html

Bổ sung kiểm tra sửa bước nguồn: hai đáp ứng lỗi thật vẫn bị từ chối; schema giới hạn file_id theo helper có thật; cài nâng cấp từ bản v1 và chạy lại installer không ghi thừa. Không có kiểm thử nào được dùng để tuyên bố độ chính xác AI.

Kiểm tra bổ sung cơ chế sửa: 18 điều kiện dựa trên phản hồi lỗi thật và transport giả lập; kiểm tra chỉ sửa một lần, không thử lại timeout/cắt token, không đổi lượt cũ, không gọi lại mẫu đã hoàn tất, lưu riêng phản hồi sửa, đúng giới hạn 3 cuộc gọi mới của lượt tiếp tục, và nâng cấp từ bản v2. Transport giả lập chỉ kiểm tra xử lý lỗi/lưu vết, không chứng minh chất lượng Qwen.
