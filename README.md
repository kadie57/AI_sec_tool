# AI_sec_tool

AI_sec_tool thu thập cảnh báo SonarQube trên mã Java và hỗ trợ thẩm định SQL Injection, Path Traversal và Command Injection. Sau khi phân tích, người dùng có thể xem bằng chứng, thẩm định và xuất báo cáo. Luồng đánh giá khóa luận dùng bộ mẫu và nhãn tham chiếu đã chốt riêng.

## Chạy từ thư mục dự án

```bash
python3 scripts/ai_sec.py collect
python3 scripts/ai_sec.py analyze --from-run runs/20261011T121215Z-15797d --check
python3 scripts/ai_sec.py analyze --from-run runs/20261011T121215Z-15797d
.venv_review_ui/bin/python scripts/ai_sec.py review
```

Lệnh phân tích nhận cảnh báo từ lượt thu thập đã lưu. Chế độ `--check` kiểm tra nguồn và cấu hình mà không gọi SonarQube, Joern hoặc Ollama. Flask mở ở `http://127.0.0.1:5050`. Các tham số của lệnh cũ được truyền tiếp sau tên luồng. Với các lệnh thu thập, phân tích và OWASP, đường dẫn tương đối được tính từ gốc dự án.

## Tìm mã theo luồng dữ liệu

| Bước | Vị trí | Trách nhiệm |
| --- | --- | --- |
| Thu thập và định tuyến | [core/](core/) | Quét và lưu cảnh báo; phân tuyến theo rule và kiểm tra hash nguồn trước khi phân tích. |
| Lấy ngữ cảnh và bằng chứng | [evidence/](evidence/) | Chuẩn bị ngữ cảnh và đọc thêm nhánh Java cho Path. Mỗi analyzer gọi Joern theo cửa sổ dòng của cảnh báo. |
| Nhận định, kiểm chứng và ghép kết quả | [SQL](analyzers/sql/), [Path](analyzers/path/), [Command](analyzers/command/) | Dựng yêu cầu Ollama, kiểm tra phản hồi và hợp nhất nhận định cùng bằng chứng. Nhánh SQL tích hợp dùng CPG để kiểm tra điều kiện phân tích; yêu cầu SQL của Ollama dùng mã nguồn có số dòng. |
| Lưu, thẩm định và xuất báo cáo | [runs/](runs/), [review_ui/](review_ui/), [ui_report_v1/](ui_report_v1/) | Lưu manifest, kết quả và bằng chứng từng lượt; hiển thị, thẩm định và xuất CSV, HTML hoặc PDF. |
| Đánh giá và phân tích lại | [OWASP](experiments/tools/owasp/), [SQL replay](experiments/tools/sql_replay/) | Kiểm tra bộ mẫu đã chốt, dùng lượt thu thập đã lưu và phân tích lại các ca SQL đã lưu khi có yêu cầu riêng. |
| Lệnh chạy và kiểm tra | [scripts/](scripts/), [tests/](tests/), [docs/](docs/) | Lệnh theo luồng, kiểm tra launcher và tài liệu vận hành. |

Các liên kết tương đối trong thư mục theo chức năng trỏ tới một bản mã duy nhất. Một số entry point và module vẫn đặt tại gốc vì các script đánh giá và checkpoint dùng đường dẫn và SHA-256 của chúng. Dùng `scripts/ai_sec.py` hoặc entry point gốc khi chạy. Kết quả, mã mẫu, nhãn và bằng chứng nằm ở đường dẫn của từng lượt thực nghiệm.

### Kiểm tra các bước đánh giá OWASP

```bash
python3 scripts/ai_sec.py owasp-plan --verify
python3 scripts/ai_sec.py owasp-collect --check
python3 scripts/ai_sec.py owasp-analyze --from-run runs/owasp-holdout-20261115T151839Z-b04660 --check
```

Các lệnh này kiểm tra đúng phiên bản và tập mẫu đã chốt. Nếu lệch hash hoặc thiếu file, dùng bản sao đúng phiên bản để tái lập. Xem thêm [hướng dẫn pipeline ba nhóm](docs/README_multi_v1.md) và [ghi chú giải thích SQL](docs/README_EXPLANATION_V2.md).

---

# Sửa phạm vi lời giải thích nguồn — 2026-10-21

Chép hai file Python vào ~/AI_sec_tool, thay đúng hai file cùng tên sau khi sao lưu.

## Thay đổi

- path_triage_v2.py: giới hạn lời giải thích nguồn ở nguồn dữ liệu và đường truyền; việc đánh giá bảo vệ thuộc bước phân tích đường dẫn. Yêu cầu tiếng Việt và bằng chứng đúng dòng.
- source_audit_v2.py: yêu cầu mô tả caller/nguồn còn thiếu bằng đúng định danh trong mã, không lấy ví dụ main/HTTP trong prompt làm dữ kiện của mẫu.

Giữ nguyên schema, mô hình, tùy chọn sinh, hàm quyết định nhãn, kiểm tra bằng chứng, Joern và prompt phân tích tác động đường dẫn. Không gán nhãn theo tên mẫu. Không sửa kết quả cũ.

## Kiểm tra đã thực hiện

Biên dịch cú pháp hai file thành công. So sánh cây cú pháp với file gốc xác nhận chỉ thay VERSION và thêm hướng dẫn nguồn. Chưa gọi mô hình trên máy người dùng: kiểm tra này không chứng minh chất lượng lời giải thích đã cải thiện.

## Chạy kiểm tra tích hợp

```bash
python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d --check
```

## Chạy lại năm mẫu

```bash
OLLAMA_TIMEOUT=900 python3 master_pipeline_multi_v1.py \
  --from-run runs/20261011T121215Z-15797d \
  --only-component project_1:Clean_Code/pilot_path22/PathCase01.java \
  --only-component project_1:Clean_Code/pilot_path22/PathCase02.java \
  --only-component project_1:Clean_Code/VulnerablePath.java \
  --only-component project_1:Clean_Code/lab/Case03.java \
  --only-component project_1:Clean_Code/lab/Case01.java
```

Cần Ollama và Docker/Joern hoạt động. Dùng lại dữ liệu quét; mã nguồn phải còn khớp hash của lượt thu thập. Tối đa 12 lượt gọi AI, có thể ít hơn nếu điều kiện chặn hoặc checkpoint áp dụng. Không sửa các file trong khi chạy.

Gửi ai_results.json và manifest.json trong thư mục kết quả mới được lệnh in ra.

## Tiêu chí đối chiếu

- PathCase02: phần nguồn không tự kết luận thiếu kiểm tra bảo vệ; phần đường dẫn mô tả đúng guard và nhánh thoát. Không khẳng định an toàn filesystem tuyệt đối từ regex.
- Case03: mô tả thiếu caller/nguồn của username và password trong lookup; không tự đưa main vào mã. Với ngữ cảnh hiện có, giữ UNKNOWN là phù hợp.
- PathCase01, VulnerablePath và Case01 là đối chứng để phát hiện thay đổi ngoài ý muốn. Đối chiếu cả nhãn, lời giải thích và dòng bằng chứng, không chỉ đếm nhãn đúng.
- Nếu lời giải thích vẫn sai hoặc có lỗi ngữ cảnh/token, giữ kết quả mới để chẩn đoán; không coi bản sửa prompt là bảo đảm đúng.
