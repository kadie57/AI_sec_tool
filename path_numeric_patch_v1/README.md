# Kiểm tra mâu thuẫn chuyển kiểu số — v1
Cài sau path_guard_patch_v1; installer kiểm tra SHA và sao lưu trước khi sửa.

Từ ~/AI_sec_tool:
python3 path_numeric_patch_v1/install.py
python3 path_numeric_patch_v1/replay.py --run runs/multi-20261021T160018Z-9bb79a-35cce10e6703

Không gọi AI; replay dùng source snapshot đúng SHA, giữ nguyên kết quả cũ.
Đây là kiểm tra cấu trúc giới hạn, không phải trình kiểm chứng Java tổng quát.
Chỉ nhận một main theo đúng grammar; Long.toString(Long.parseLong(value)), giá trị không bị ghi đè, File(String) đọc trực tiếp. Giả định java.lang chuẩn, không có lớp cùng package che Long/System/String.
Không chứng minh filesystem confinement (symlink/quyền truy cập). Khi AI báo ESCAPABLE trái căn cứ chuỗi số, chuyển UNKNOWN để thẩm định, không tự kết luận FP.
AI facts gốc được giữ nguyên; numeric_check chứa căn cứ riêng. Không tăng điểm accuracy cho AI, không phải đánh giá độc lập trên mẫu mới.
Bộ kiểm tra catch trước đó giữ nguyên. Các cấu trúc ngoài phạm vi trả NOT_CHECKED, không đổi nhãn.
Hoàn tác: phục hồi path_triage_v2.py từ thư mục backups được installer in ra; module numeric có thể giữ vì sẽ không được import.
