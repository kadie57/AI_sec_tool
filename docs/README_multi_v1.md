# Một lệnh phân tích ba nhóm cảnh báo

Đặt master_pipeline_multi_v1.py vào ~/AI_sec_tool, cạnh các module hiện có.
Không thay thế master_pipeline.py, các module AI hoặc review_ui.

## Kiểm tra trước (không gọi dịch vụ)

```bash
cd ~/AI_sec_tool
python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d --check
```

Script kiểm tra nguồn còn khớp lần quét, cấu hình SQL đã cố định và module Path/Command.
Kết thúc hợp lệ: MULTI_CHECK_OK. Nếu thiếu module hoặc baseline, gửi nguyên lỗi;
không sửa hash hoặc bỏ các bước kiểm tra để chạy tiếp.

## Chạy phân tích

Sau khi kiểm tra thành công, cần Docker hoạt động, image Joern đã có và Ollama
phục vụ model 14B đúng digest SQL. Không cần SonarQube/token khi dùng lần quét đã lưu.

```bash
OLLAMA_TIMEOUT=900 python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d
```

Script KHÔNG quét SonarQube lần nữa. Đây là một lượt phân tích mới trên cảnh báo
đã thu thập, không nhập kết quả hoặc thẩm định từ các lần chạy standalone trước.
Nó in giới hạn số lần gọi AI trước khi chạy: tối đa 3 lần/cảnh báo SQL và
2 lần/cảnh báo Path/Command; không gọi AI cho rule ngoài phạm vi hoặc cảnh báo
không vượt qua các điều kiện của module. Không đánh giá độ chính xác từ con số này.

Kết quả ở runs/multi-<tên-lần-quét>-<hash>/, có manifest.json, ai_results.json,
source_snapshot/, và các artifact issue-XXXX để giao diện hiện có đọc trực tiếp.
Nguồn được chụp lại trước khi phân tích; SQL cũng đọc snapshot thay vì file đang sửa.
Danh sách kết quả bao gồm cả cảnh báo SKIPPED. SKIPPED/UNKNOWN không có nghĩa an toàn.

## Tiếp tục sau khi dừng

Chạy lại cùng lệnh: các cảnh báo có checkpoint hoàn tất được dùng lại, kể cả lỗi
đã ghi. Không tự retry lỗi. Thay đổi module/cấu hình tạo định danh lượt mới;
đổi model/Joern giữa một lượt còn dở bị chặn.

Nếu một cảnh báo đã bắt đầu nhưng chưa có checkpoint, script dừng và chỉ rõ.
Muốn chạy lại riêng cảnh báo dở đó:

```bash
OLLAMA_TIMEOUT=900 python3 master_pipeline_multi_v1.py --from-run runs/20261011T121215Z-15797d --retry-incomplete
```

Bản dở được chuyển vào interrupted/, không xóa. Cảnh báo đang dở có thể lặp lại
đến 3 lần gọi AI; resume hiện theo cảnh báo, không theo từng bước AI.
Không chạy đồng thời hai terminal cho cùng lượt. Script khóa lượt bằng flock.

## Phạm vi

- SQL: findsecbugs:SQL_INJECTION_JDBC, findbugs:SQL_INJECTION_JDBC, java:S3649;
  chỉ khi registry SQL hiện có chấp nhận; giữ nguyên pipeline SQL đã cố định.
- Path: findsecbugs:PATH_TRAVERSAL_IN; module File(String) đọc file, không tự mở
  rộng sang ghi file hoặc các API khác.
- Command: findsecbugs:COMMAND_INJECTION; giữ nguyên điều kiện direct exec
  và luật danh sách IPv4 hữu hạn của command_triage_v2.py. Không hỗ trợ mọi shell/API.

Nhãn AI, kết quả hệ thống và thẩm định được giữ riêng. Không tự đóng cảnh báo,
không fine-tune và không tuyên bố mô hình hiểu đúng mọi trường hợp.
Thẩm định ở các lượt cũ vẫn ở nguyên đó; không tự coi chúng là thẩm định lượt mới.

## Kiểm tra phát triển

Bộ điều phối đã được kiểm tra bằng fixture/mô phỏng dịch vụ: ba route và SKIPPED,
Command giữ UNKNOWN của AI khi luật đề xuất LIKELY_FP, snapshot/hash, checkpoint,
chặn checkpoint bị sửa, tiếp tục không gọi lại dịch vụ khi đã đủ kết quả,
retry cảnh báo dở và giữ nguyên file thẩm định. Chưa chạy SonarQube/Joern/Ollama
thật trong môi trường phát triển; --check trên máy bạn đối chiếu baseline thực tế.
