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
