# Path: phạm vi kết luận và bằng chứng — bản v4

Thay path_triage_v2.py trong ~/AI_sec_tool sau khi sao lưu file cũ. source_audit_v2.py được giữ nguyên từ gói trước, chỉ kèm để bảo toàn gói cập nhật; không cần chép lại nếu đã cài.

Thay đổi: bổ sung hướng dẫn dẫn dòng đọc nguồn; phân biệt điều kiện khai thác với bằng chứng nguồn; phân biệt giới hạn tên file với đích file thực tế; yêu cầu dẫn guard và nhánh thoát. Không gán đáp án theo tên mẫu. Không thay schema, mô hình, tùy chọn, validator, Joern hay hàm quyết định. Đây là cải tiến prompt, không phải bộ chứng minh ngữ nghĩa.

Đã kiểm tra cú pháp và đối chiếu AST: chỉ phiên bản Path và phần bổ sung prompt thay đổi. Chưa chạy Ollama trong môi trường người dùng. Phải đối chiếu kết quả thực tế, không coi nhãn giữ nguyên là điều kiện bắt buộc. Nếu có CONTEXT_LIMIT, gửi kết quả để điều chỉnh; không bỏ kiểm tra giới hạn.

Kiểm tra tích hợp:
```bash
python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d --check
```

Chạy riêng ba mẫu Path, tối đa 6 lượt gọi AI:
```bash
OLLAMA_TIMEOUT=900 python3 master_pipeline_multi_v1.py \
  --from-run runs/20261011T121215Z-15797d \
  --only-component project_1:Clean_Code/pilot_path22/PathCase01.java \
  --only-component project_1:Clean_Code/pilot_path22/PathCase02.java \
  --only-component project_1:Clean_Code/VulnerablePath.java
```

Cần Ollama và Docker/Joern. Dùng lại dữ liệu quét, không cần quét SonarQube lại. Không sửa file trong khi đang chạy. Kết quả cũ giữ nguyên.

Gửi ai_results.json và manifest.json từ thư mục mới được in ra.

Tiêu chí: PathCase01 dẫn thao tác đọc args bên cạnh xây dựng đường dẫn; PathCase02 mô tả guard và phạm vi bảo vệ chính xác, không suy diễn filesystem; VulnerablePath không khẳng định người ngoài kiểm soát tham số khi chưa thấy caller. UNKNOWN có căn cứ không phải lỗi chạy. So sánh nhãn, lời giải thích, bằng chứng và thông tin thiếu; không suy ra độ chính xác tổng quát từ ba mẫu phát triển.
