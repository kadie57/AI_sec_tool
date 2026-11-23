BỘ ĐÁNH GIÁ TIẾP THEO SQL89 — 6 MẪU

Giải nén thư mục eval_sql89_new_v1 vào ~/AI_sec_tool.
1. cd ~/AI_sec_tool/eval_sql89_new_v1
2. python3 run_eval.py --check
   Biên dịch 6 file, không chạy Java, không kết nối DB, kiểm tra cấu hình pipeline,
   lưu hash vào frozen_config.json. Không sửa/xóa file mốc này để vượt kiểm tra.
3. python3 run_eval.py --collect
   Dùng SONAR_TOKEN hiện có; quét project riêng sql89_followup_v1.
   Chỉ quét và lấy cảnh báo. Không gọi AI/Joern. Kết quả ở runs/ trong thư mục này.
   Token phải có quyền phân tích/tạo project riêng. Không gửi token vào chat.
4. Gửi manifest.json, issues.json và rule_inventory.json của lượt collect.
   Trước khi phân tích, xác minh quality profile và rule SQL giống project cũ.
5. Sau đối chiếu phạm vi: OLLAMA_TIMEOUT=900 python3 run_eval.py --analyze
   Bước này quét mới và gọi pipeline đã cố định trên 6 mẫu, không quét bộ cũ.
   Chỉ thực hiện khi đã xem kết quả collect. Tối đa 3 lời gọi AI/cảnh báo phù hợp;
   chưa có resume toàn lượt. Đây không phải lệnh cần chạy ngay lúc nhận gói.

reference_labels.json là đáp án để người thẩm định đọc, không phải input AI.
Không đổi đáp án dựa trên đầu ra AI. Mẫu an toàn không có cảnh báo Sonar không
được tính là AI dự đoán FP đúng. Ghi riêng: Sonar không báo, Joern không có flow,
lỗi gọi AI, UNKNOWN do thiếu ngữ cảnh, nhãn TP/FP và chất lượng giải thích.
Mã các mẫu không chứa tên/nhận xét gợi đáp án. Runner không đọc đáp án.
Bộ này được soạn mới nhưng có họ mẫu gần bộ phát triển; không đại diện độ chính
xác tổng quát. Giữ nguyên prompt sau khi bắt đầu đánh giá. Nếu sửa, tách phiên bản.
Không thực thi các lớp Java; chỉ biên dịch và phân tích tĩnh.
