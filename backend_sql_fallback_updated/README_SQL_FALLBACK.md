# SQL no-flow fallback v1 — 15/10/2026

## Nội dung
- master_pipeline.py: Joern xuất số lời gọi và số đối số SQL tại đúng vùng dòng cảnh báo.
- Parser kiểm tra khối kết quả, số flow và bằng chứng. Kết quả cũ thiếu số sink vẫn đọc được nhưng không cấp quyền fallback.
- master_pipeline_multi_v1.py: bật fallback cho SQL, đổi router version và lưu cấu hình vào context.
- Chỉ khi Joern thành công, flow_count=0, sink_call_count=1 và sink_argument_count=1 mới chạy phân tích mã bằng nhánh AI SQL hiện có.
- Joern lỗi, không tìm sink, sink mơ hồ hoặc vượt giới hạn ngữ cảnh không được đi qua fallback.
- Không sửa prompt, model, luật ánh xạ nhãn hoặc nhánh Path/Command. Không gán FP theo tên file.
- Kết quả mới có analysis_mode=SOURCE_ONLY_NO_FLOW, flow_count=0, cpg_usage và analysis_limitations. Không giả lập bằng chứng flow.
- Cờ llm_invoked đánh dấu đã gọi adapter AI, không chứng minh dịch vụ đã hoàn tất.
- Không có flow không chứng minh an toàn. Nhãn mới vẫn cần thẩm định.
- Nhận dạng lời gọi dựa trên tên API và dòng; chưa phải phân giải kiểu Java đầy đủ.

## Cài đặt
Dừng tiến trình pipeline đang chạy trước khi thay file. Không cần dừng Flask nếu chỉ đang xem dữ liệu cũ.
Trong ~/AI_sec_tool, sao lưu hai file cũ:

```bash
mkdir -p backups/sql_fallback_before_20261015
cp -n master_pipeline.py master_pipeline_multi_v1.py backups/sql_fallback_before_20261015/
```

Giải nén gói vào ~/AI_sec_tool, thay đúng hai file .py. Các module còn lại giữ nguyên.

## Kiểm tra trước khi gọi AI
```bash
cd ~/AI_sec_tool
python3 test_sql_fallback.py
python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d --only-component project_1:Clean_Code/pilot_sql89/Trial07.java --check
```
--check kiểm tra cấu hình và hash nguồn; không gọi dịch vụ hoặc tạo lượt chạy.
Nếu hash khác lần quét: dừng kiểm tra nguồn; không bỏ qua kiểm tra hash.

## Chạy riêng Trial07
SonarQube không cần quét lại. Cần Docker/Joern đã có và Ollama với mô hình cũ.
```bash
OLLAMA_TIMEOUT=900 python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d --only-component project_1:Clean_Code/pilot_sql89/Trial07.java
```
Tối đa 3 lượt gọi AI; không phải huấn luyện. Gửi ai_results.json của thư mục KẾT QUẢ mới.
Không dùng thư mục multi cũ làm --from-run: dùng lượt thu thập gốc như trên.

## Đối chứng sau khi kiểm tra Trial07
```bash
OLLAMA_TIMEOUT=900 python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d --only-component project_1:Clean_Code/pilot_sql89/Trial01.java --only-component project_1:Clean_Code/pilot_sql89/Trial04.java --only-component project_1:Clean_Code/pilot_sql89/Trial06.java
```
Tối đa 9 lượt gọi AI. Đối chiếu nhãn và lời giải thích với mã nguồn, không chỉ kiểm tra nhãn.
Các lựa chọn tạo lượt con riêng, có evaluation_scope và selected_components trong manifest.
Số cảnh báo của lượt con không phải tổng số cảnh báo của dự án. Không gộp các lượt chạy lại như các mẫu độc lập.
--only-component chỉ chọn rule được hỗ trợ của component đó. Có thể lặp tùy chọn.

## Dữ liệu và tiếp tục chạy
Phiên bản/cấu hình mới tạo thư mục kết quả mới, giữ nguyên kết quả và thẩm định cũ.
Chạy lại đúng lệnh sẽ bỏ qua checkpoint hoàn tất, kể cả kết quả lỗi.
Nếu dừng giữa một cảnh báo, --retry-incomplete lưu bản dở riêng rồi chạy lại cảnh báo đó; có thể lặp các lần gọi AI.
Không cập nhật số liệu báo cáo trước khi chạy/thẩm định bản sửa.

## Kiểm chứng trong môi trường phát triển
7 unittest offline đạt; kiểm tra cú pháp hai module đạt.
Các test dùng mock để xác minh điều kiện gọi AI, không xác minh chất lượng dự đoán của LLM hoặc chạy thực tế Joern.
Chưa chạy toàn bộ pipeline với dịch vụ trên laptop người dùng.
