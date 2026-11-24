# AI_sec_tool_update — Chuẩn bị bằng chứng SQL/JDBC

Thư mục này chứa luồng SonarQube → cảnh báo SQL → kiểm tra mã nguồn → bằng chứng Joern và helper → thẩm định bằng Ollama. Bước chuẩn bị xuất một bản ghi JSONL cho mỗi cảnh báo.

## Cấu trúc thư mục

```text
AI_sec_tool_update/
├── collect_sonar_sql.py          # Thu thập cảnh báo và hash Java
├── prepare_sql_evidence.py       # Chuẩn bị sql_evidence.jsonl
├── sql_llm_experiment.py         # Gọi Ollama và so sánh lượt chạy
├── sql_pipeline/
│   ├── cwe_mapper.py             # Ánh xạ rule sang CWE
│   ├── run_io.py                 # Ghi JSON và log, chạy công cụ
│   └── evidence/
│       ├── joern_sql.py          # Định vị đối số JDBC và lấy luồng
│       ├── source_text.py        # Che chú thích, giữ tọa độ gốc
│       ├── sql_context_bundle_v1.py  # Ghép helper đúng commit
│       ├── sql_evidence_selection.py # Chọn tọa độ gửi cho Ollama
│       ├── sql_endpoint_specifications.py # Thêm bằng chứng về vai trò API
│       ├── sql_source_paths.py   # Nối nguồn HTTP đã xác minh tới JDBC qua nhiều tệp
│       ├── SqlEndpointProbe.java # Phân giải chữ ký từ snapshot bằng JDK
│       └── SqlValueEvidence.java # Xác minh giá trị tới đối số SQL
├── tests/                       # Kiểm tra hồi quy
├── fixtures/sql8/               # Cảnh báo, snapshot Java, kết quả Joern đã lưu
├── runs/                        # Đầu ra, baseline và hồ sơ thực nghiệm
└── requirements.txt
```

Chạy kiểm tra hồi quy từ `AI_sec_tool_update/` bằng `python3 -m unittest discover -v`. Các lệnh chạy pipeline bên dưới dùng ba script ở thư mục gốc của `AI_sec_tool_update`.

## Chạy thử offline trên tám cảnh báo

Chạy từ `AI_sec_tool_update/`.

```bash
python3 prepare_sql_evidence.py \
  --from-run fixtures/sql8 \
  --source-root fixtures/sql8/sources \
  --recorded-joern fixtures/sql8/joern \
  --output runs/sql8-evidence
```

Chế độ này đọc lại các artifact Joern đã lưu và đối chiếu cảnh báo, vùng dòng và hash. Có thể thay `--output runs/sql8-evidence` bằng `--check` để kiểm tra đầu vào mà không ghi hồ sơ mới.

Bộ chuẩn bị tự tìm repo tại `~/AI_sec_benchmarks/BenchmarkJava`, hoặc theo `OWASP_BENCHMARK_ROOT` hay `--benchmark-root`. Helper chỉ được ghép khi mã chính khớp Git object tại commit trong manifest. Khi thiếu repo hoặc commit phù hợp, đầu ra vẫn giữ file chính và ghi thông tin thiếu.

## Đường đi và ngữ cảnh gửi cho Ollama

`selected_evidence` thêm tối đa ba đường đi ứng viên theo thứ tự Joern trả về. Mỗi đường giữ tọa độ nguồn, đối số SQL và tối đa mười bước trung gian. Vùng mã quanh hai đầu và các cấu trúc điều khiển gần đường đi được chỉ bằng số dòng gốc của `F0`. Request vẫn gửi các dòng mã và helper đã chuẩn bị. Bảng Joern gốc vẫn nằm trong `cpg_evidence.json` để đối chiếu.

Các bước được chọn là vị trí trên đường đi ứng viên của phân tích tĩnh. Các nhánh gần đó giúp người đọc xem điều kiện và giá trị thay thế. Nguồn bên ngoài, nhánh thực thi và truyền dữ liệu giữa các tệp vẫn có thể chưa xác định. Khi bảng đường đi thiếu tọa độ hoặc không có luồng, trường `sink_status` cho biết truy vấn Joern tìm thấy gì trong vùng cảnh báo.

```bash
python3 sql_llm_experiment.py run runs/sql8-evidence/sql_evidence.jsonl --out runs/sql8-llm
python3 sql_llm_experiment.py compare runs/sql8-baseline-2026-11-24/llm runs/sql8-llm
```

Thêm `--dry-run` vào lệnh `run` để lưu request mà không gọi Ollama. Mỗi lệnh `run` cần một thư mục đầu ra mới. Kết quả `compare` đếm trạng thái trước và sau. Đánh giá đúng sai cần ghép nhãn tham chiếu riêng sau khi mô hình trả kết quả.

### Trình bày bằng chứng theo từng đường đi

Thêm `--path-snippets` vào lệnh `run` để trình bày từng đường đi ứng viên thành `Source → Steps → Sink` trong cùng một request cho mỗi cảnh báo. Mỗi bước mang đoạn mã với tọa độ gốc như `F0:55`. Gói trích các dòng liên quan từ tệp chính và giữ mã helper đã chuẩn bị. Khi thiếu đường đi, gói vẫn có đoạn mã quanh vùng cảnh báo. Bộ kiểm tra trích dẫn dùng các dòng thực sự được trình bày.

Để đo riêng định dạng này trên SQL8, dùng `runs/sql8-endpoint-specifications/evidence/sql_evidence.jsonl` cho cả hai lượt và thêm `--path-snippets` ở lượt thử. Gói đầu vào này đã có đặc tả source/sink và chưa có trường bằng chứng giá trị JDBC.

### Nhận định giá trị đã xác minh ở Sink

Thêm `--verified-sink-note` cùng `--path-snippets` khi đầu vào đã có bằng chứng từ `--infer-jdbc-values`. Tùy chọn đưa một nhận định ngắn cùng các dòng hỗ trợ vào đúng `Sink` nếu phân tích xác minh được giá trị của một đối số SQL duy nhất. Với ca chưa đủ bằng chứng hoặc chưa đối chiếu được lời gọi JDBC, request dùng gói trích đoạn như cũ. Dữ liệu bao gồm các ca `unknown` vẫn nằm trong hồ sơ JSONL.

```bash
python3 sql_llm_experiment.py run \
  runs/sql8-jdbc-value-evidence/evidence-v2/sql_evidence.jsonl \
  --path-snippets --verified-sink-note --dry-run --out runs/sql8-verified-sink-note-replay
```

Tùy chọn `--structured-sink-evidence` dùng cùng `--path-snippets` thay cho `--verified-sink-note` để trình bày cùng nhận định theo vai trò. Khối `Sink` có dòng JDBC được cảnh báo, mã của nhánh đã xác minh, chuỗi giá trị tới đối số SQL và các tọa độ hỗ trợ trích dẫn. Các dòng dùng trong khối lấy từ đoạn mã vốn đã được gửi. Có thể chạy đối chứng bằng lệnh trên với tùy chọn mới và thư mục đầu ra riêng.

## Xác minh source và sink theo từng cảnh báo

Thêm `--infer-specifications` vào bước chuẩn bị. Tùy chọn cần JDK 17 trở lên. `--java-classpath` nhận đường dẫn đến từng JAR cục bộ để phân giải API Java bên ngoài. Ví dụ, bộ SQL8 dùng `javax.servlet` từ JAR `javaee-api` tại Maven cache cục bộ. Thay đường dẫn bằng JAR tương ứng trên máy đang chạy.

```bash
python3 prepare_sql_evidence.py \
  --from-run fixtures/sql8 --source-root fixtures/sql8/sources \
  --recorded-joern fixtures/sql8/joern --infer-specifications \
  --java-classpath ~/.m2/repository/javax/javaee-api/8.0.1/javaee-api-8.0.1.jar \
  --output runs/sql8-specifications-replay
```

`selected_evidence.endpoint_specifications` ghi chữ ký JDBC và tọa độ đối số SQL trong vùng cảnh báo. Các giá trị bind được ghi riêng nếu xác định được cùng một biến statement cục bộ chưa bị gán lại. Với Servlet, bộ phân tích nhận diện chữ ký đọc request và có thể theo tới một helper trả trực tiếp kết quả của lời gọi này. Kết quả ghi rõ khi chỉ phân giải được khai báo của helper hoặc thiếu symbol. Manifest lưu SHA‑256 của các JAR đã chỉ định.

Phạm vi xác minh là snapshot tệp chính và các helper đã được ghép. Probe phân tích bằng JDK với annotation processing tắt. Nó chỉ ghi nhận vai trò API và vị trí có căn cứ. Đường từ dữ liệu HTTP đến JDBC và nhánh thực thi vẫn cần bằng chứng riêng. Ollama đọc các nhận định này ở bước thẩm định cuối.

## Bằng chứng nhánh và giá trị tới JDBC

Thêm `--infer-jdbc-values` vào lệnh trên và chọn thư mục đầu ra mới. Tùy chọn dùng `javac` và yêu cầu `--infer-specifications`. Pipeline thêm `selected_evidence.jdbc_value_evidence` ngay trong gói gửi cho Ollama. Mỗi mục gắn với chữ ký JDBC và vị trí đối số SQL đã được xác minh.

Bộ phân tích dùng AST và symbol của JDK. Nó theo biến cục bộ, một số biểu thức hằng, nhánh `if` và `switch` có điều kiện xác định, phép ghép chuỗi và lời gọi helper có thể xác định đích. Các kết quả `constant_sql_text` và `external_input_contributes` có tọa độ giải thích. Với `unknown`, gói có thể ghi vị trí phép ghép chuỗi, khai báo biến SQL hoặc nơi phân tích dừng. Phân tích có giới hạn độ sâu helper và số bước. Kết quả mô tả đường Java được phân tích tới lời gọi, chưa kết luận đúng sai của cảnh báo.

Bộ phân tích tính `+`, `-`, `*`, `/`, `%` và so sánh thứ tự với toán hạng `int` hoặc `char` có giá trị đã xác định. Phép tính tuân theo ngữ nghĩa `int` của Java, gồm tràn số và chia lấy phần nguyên. Khi toán hạng phụ thuộc runtime hoặc phép chia có mẫu số 0, giá trị vẫn ở trạng thái `unknown`. Gói `--structured-sink-evidence` có thể thêm đúng dòng định nghĩa hằng cần để kiểm tra phép tính, kể cả khi dòng đó nằm ngoài trích đoạn Joern.

Để đối chứng, tạo hai gói từ cùng một tập cảnh báo. Lượt đầu dùng `--infer-specifications`. Lượt thứ hai thêm `--infer-jdbc-values`. Chạy Ollama với cùng model, cấu hình và bộ kiểm tra trích dẫn. `python3 -m unittest discover -v` chạy các kiểm thử nhánh, gồm nhánh giữ dữ liệu bên ngoài và nhánh chọn giá trị hằng.

Có thể thêm `--confirmed-jdbc-values-only` vào lệnh `sql_llm_experiment.py run` để thử cách trình bày chỉ gửi bằng chứng giá trị đã xác minh. Tùy chọn bỏ trường này khỏi request khi phân tích còn `unknown` hoặc có nhiều đối số SQL ứng viên. Hồ sơ bằng chứng vẫn chứa tọa độ đã thu được.

## Đường đi liên tệp từ nguồn HTTP

Thêm `--joern-source-paths` cùng `--infer-specifications` khi chuẩn bị dữ liệu. Sau khi JDK phân giải chữ ký API, Joern nạp tệp Java chính và các helper đã kiểm tra phiên bản. Truy vấn bắt đầu từ lời gọi Servlet đọc HTTP đã xác minh và dừng ở đối số văn bản SQL của lời gọi JDBC đã đối chiếu. Tùy chọn này chạy Joern cục bộ, kể cả khi `--recorded-joern` được dùng để tái sử dụng truy vấn nền. Cần image Joern có sẵn trên máy.

Khi chạy LLM với `--path-snippets`, đường mới được trình bày theo Source → Steps → Sink với mã và tọa độ gốc ở từng tệp. Các đích gọi đa hình Joern tìm thấy đi kèm vị trí khai báo để người thẩm định đối chiếu. Đường ứng viên cần được xem cùng nhánh và bằng chứng giá trị JDBC. Kết quả của truy vấn mới nằm trong `selected_evidence.anchored_paths` và log từng cảnh báo. Ca thiếu source hoặc sink đủ rõ tiếp tục dùng gói bằng chứng nền.

Cách trích đoạn quanh hai đầu mút và chọn bước trung gian dựa trên phần [Contextual Analysis của IRIS](https://github.com/iris-sast/iris/blob/main/src/modules/contextual_analysis_pipeline.py).

```bash
python3 prepare_sql_evidence.py \
  --from-run fixtures/sql8 --source-root fixtures/sql8/sources \
  --recorded-joern fixtures/sql8/joern --infer-specifications \
  --java-classpath "$JAVAEE_API_JAR" --infer-jdbc-values --joern-source-paths \
  --output runs/sql8-anchored-evidence

python3 sql_llm_experiment.py run runs/sql8-anchored-evidence/sql_evidence.jsonl \
  --path-snippets --structured-sink-evidence --out runs/sql8-anchored-llm
```

Đặt `JAVAEE_API_JAR` thành đường dẫn tới JAR chứa API Servlet của bộ mẫu. Thêm `--dry-run` vào lệnh thứ hai để xem các request đã chuẩn bị.

Thêm `--bind-warning-citation` vào lệnh `sql_llm_experiment.py run` để gắn dòng đầu của vùng cảnh báo khi Qwen đưa ra kết luận TP/FP có trích dẫn hỗ trợ hợp lệ nhưng bỏ sót dòng cảnh báo. Dòng được gắn phải có trong mã hiển thị. Kết quả lưu nguồn gốc của dòng bổ sung ở `warning_citation_added` và giữ phản hồi Ollama để đối chiếu. Manifest ghi phiên bản kiểm tra riêng để nhận biết khi so sánh các lượt chạy.

Thêm `--prompt-profile iris-contextual` vào lệnh `run` để thử prompt lấy ý tưởng từ mục 3.5 của [bài báo IRIS](https://proceedings.iclr.cc/paper_files/paper/2025/file/582d4e27fa24168f3af1f4582655034b-Paper-Conference.pdf). Qwen nêu căn cứ và trích dẫn trước nhãn, phân biệt văn bản SQL với giá trị được bind, và kiểm tra bằng chứng Java theo đúng nhánh trước khi dựa vào đường ứng viên Joern. Gói bằng chứng, các nhãn và cách kiểm tra kết quả dùng cùng định dạng như trước. Lệnh mặc định chọn `baseline`. Khi đối chứng hai prompt, dùng cùng tệp bằng chứng, cùng model và cùng lựa chọn gắn trích dẫn cho cả hai lượt.

## Kiểm tra lại lượt quét đã lưu

Chạy từ `AI_sec_tool_update/`. Trong ví dụ này, `..` là thư mục dự án gốc.

```bash
python3 prepare_sql_evidence.py \
  --from-run ../runs/20261011T121215Z-15797d \
  --source-root .. \
  --only-component project_1:Clean_Code/pilot_sql89/Trial04.java \
  --check
```

Để tạo bằng chứng, thay `--check` bằng `--output runs/sql-evidence-trial04`. Bước này cần Docker và image Joern đã có trên máy. Có thể chỉ định image bằng `JOERN_IMAGE`. Đầu ra bao gồm:

- `sql_evidence.jsonl` chứa mã đã che chú thích, thông tin Joern, helper và ngữ cảnh thiếu theo từng cảnh báo.
- `evidence.json` là danh mục rule, vùng cảnh báo, hash nguồn, số lời gọi, số đối số và số luồng.
- `sources/` chứa snapshot Java đã xác minh.
- `issue-*/cpg_evidence.json` chứa đường đi từ truy vấn Joern. Cùng thư mục có log và script truy vấn.
- `manifest.json` ghi lượt thu thập nguồn, image Joern và trạng thái xuất.

Phạm vi hiện tại là một tệp Java. Số luồng từ tham số chưa xác nhận nguồn bên ngoài. Nếu truy vấn Joern không tìm thấy luồng, gói vẫn lưu kết quả đó để bước tiếp theo đánh giá.

## Thu thập lượt mới

Cài phụ thuộc bằng `python3 -m pip install -r requirements.txt` từ `AI_sec_tool_update/`. Từ thư mục dự án chứa `Clean_Code/`, chạy `python3 AI_sec_tool_update/collect_sonar_sql.py` với `SONAR_TOKEN` và các biến `SONAR_URL`, `SONAR_PROJECT_KEY`, `SONAR_SCANNER_PATH` phù hợp. Lệnh tạo một lượt thu thập mới trong `runs/` của thư mục làm việc.
