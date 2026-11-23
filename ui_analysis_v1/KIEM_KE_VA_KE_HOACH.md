# Kiểm kê ngày 28/10/2026

Căn cứ: AI_sec_tool_source_20261028_092012.zip, 77 file nguồn + FILE_LIST.
Kiểm kê mã khác với xác nhận chạy dịch vụ thật. ZIP không chứa dữ liệu runs/experiments.

## Đã có trong mã nhận được

- Backend Sonar: biên dịch/quét/chờ tác vụ/thu thập cảnh báo và hash nguồn.
- Router ba nhánh SQL JDBC, Path File(String) đọc, Command trực tiếp trong phạm vi hẹp.
- Joern, Qwen qua Ollama, source audit, checkpoint và kết quả theo lượt.
- Bộ kiểm tra mâu thuẫn catch/numeric; giữ nhận định AI riêng.
- UI lịch sử lượt chạy, tìm dự án/lượt chạy, lọc trạng thái/kết luận/thẩm định.
- Xem source snapshot, hash, dòng bằng chứng, nhận định AI/hệ thống.
- Lưu thẩm định có người thẩm định, lý do, thời gian, revision, chống ghi đè revision cũ.
- Thẩm định gắn với fingerprint bản ghi và hash nguồn; ai_results gốc không bị sửa.
- CSV theo bộ lọc, thống kê toàn lượt theo nhóm SQL/Path/Command, AI/hệ thống/người,
  trạng thái xử lý và thời gian toàn lượt.
- Chặn CSRF POST, chỉ host localhost, kiểm tra đường dẫn trong phạm vi dữ liệu.

## Bổ sung trong gói này

- Trang chọn lượt quét/file và khởi động kiểm tra hoặc phân tích AI.
- Worker nền độc lập với tab trình duyệt; khóa chống tác vụ UI trùng.
- Nhật ký/tác vụ lưu bền trên đĩa, tự cập nhật, liên kết kết quả/thẩm định.
- Nhãn tiếng Việt cho hai nguồn quyết định STATIC_GUARD_CONFLICT và STATIC_NUMERIC_CONFLICT.
- Requirements cho môi trường UI và installer có đối chiếu hash/sao lưu.

## Chưa xong / cần ưu tiên

1. Chạy một mẫu trên máy thật qua UI để xác nhận môi trường Python/Joern/Ollama.
2. Tách cấu hình SQL khỏi baseline thực nghiệm, đóng gói cấu hình có provenance/hash
   để ứng dụng có thể cài độc lập. Không bỏ kiểm tra để làm cho chạy được.
3. Hoàn thiện bước quét mới từ UI: scanner/project/token và xử lý tác vụ nền.
4. Xử lý vấn đề Command301/302 đã quan sát; không tăng accuracy bằng cách đổi nhãn tay.
5. Nâng khả năng tra cứu: lọc theo loại lỗi, phân biệt nguyên nhân UNKNOWN; báo cáo HTML in được.
6. Chốt phiên bản và đo trên mẫu đánh giá riêng, tách nhãn AI/luật/thẩm định và tỷ lệ từ chối.
7. Hoàn thiện tài liệu cài đặt, demo, báo cáo và slide.

Chưa có bằng chứng về tự sinh patch, đa-SAST, gộp lỗi đa công cụ, tự học từ thẩm định,
hoặc chấm mức khai thác/severity bằng AI. Không ghi những phần này là chức năng đã làm.

## Phân bổ 14 ngày còn lại (điều chỉnh theo hạn nộp thực tế)

- Ngày 1–3: UI chạy pipeline và quét mới; chốt môi trường/cấu hình đóng gói.
- Ngày 4–6: lỗi backend còn quan trọng, bộ lọc/nguyên nhân, báo cáo HTML.
- Ngày 7–9: kiểm thử toàn luồng, hồi quy, thực nghiệm cuối trên bộ riêng.
- Ngày 10–12: chốt mã/số liệu, viết báo cáo, hình/sơ đồ, hướng dẫn.
- Ngày 13–14: slide, diễn tập demo và dự phòng.

Không mở thêm loại lỗi, không fine-tune, không triển khai tự sửa code trong đợt này.
