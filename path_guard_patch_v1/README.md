# Path catch guard check v1

Mục tiêu: phát hiện mâu thuẫn giữa AI báo CONFINED và một cấu trúc Java
được nhận diện đầy đủ: regex từ chối -> throw -> catch cho tiếp tục ->
giá trị không đổi được ghép vào File(String) -> FileInputStream.
Không huấn luyện AI, không thực thi mã Java, không tự kết luận TP/FP.

## Cài và replay (chạy tại ~/AI_sec_tool)

Giải nén thư mục path_guard_patch_v1 vào thư mục dự án, rồi chạy:

    python3 path_guard_patch_v1/install.py
    python3 path_guard_patch_v1/replay_path_guard.py --run runs/multi-20261021T160018Z-9bb79a-35cce10e6703

Installer kiểm tra hash đúng backend được gửi, chạy tests, sao lưu trước khi
cài hai file path_triage_v2.py và path_guard_check_v1.py. Không sửa router.
Replay không gọi AI, không ghi đè bản gốc; kết quả ở experiments/path_guard_replay.
Các lượt pipeline mới gọi bộ kiểm tra sau khi tạo bản giải thích AI.
Router ghi hash dependency vào context nên tạo lượt mới cho backend đã đổi.
Không cập nhật hoặc xóa freeze.json của bộ đánh giá ban đầu để hợp thức hóa
backend mới. Các mẫu đã dùng để sửa hệ thống hiện là mẫu phát triển/hồi quy.

## Hành vi

- CATCH_CONTINUES + AI CONFINED -> UNKNOWN / STATIC_GUARD_CONFLICT.
- ai_verdict, model_assessment và bản pre_guard_result giữ nhận định ban đầu.
- evidence_lines bổ sung dòng kiểm tra, catch và điểm tạo file.
- requires_review=true; không tự đóng cảnh báo.
- CATCH_EXITS: nhận diện return hoặc throw lại ngoại lệ, không tự gán FP.
- NOT_CHECKED: cấu trúc ngoài phạm vi; không có nghĩa an toàn hoặc kiểm chứng đạt.

## Phạm vi nghiêm ngặt

Bộ phân tích token chỉ nhận MỘT lớp/MỘT main với đầy đủ cấu trúc đã mô tả,
args.length != 1, đọc args[0], regex [A-Za-z0-9_]{1,N}, File một đối số,
và try-with-resources FileInputStream. Có thể đổi tên biến/lớp, khoảng trắng,
comment, dùng tên đầy đủ hoặc import java.io.File/FileInputStream.
Catch chỉ nhận rỗng, println chuỗi literal, return hoặc throw lại biến catch.
Không nhận catch phức tạp, finally, gán lại giá trị, guard bổ sung, các hàm khác,
escape/unicode escape, import wildcard, kiểu File khác, constructor hai đối số.
Đây không phải bộ phân tích Java tổng quát, không chứng minh khả năng khai thác
hay trạng thái filesystem. Không kiểm tra symlink/quyền truy cập/race.
Bản này KHÔNG giải quyết nhận định sai về Long.parseLong ở Sample202 hay Command.

## Kiểm tra đã thực hiện

7 nhóm kiểm thử: catch tiếp tục/rỗng, return/rethrow, cấu trúc phức tạp bị từ
chối, comment, sai dòng cảnh báo, giữ kết quả AI gốc/không đổi TP hoặc UNKNOWN.
Replay offline trên ba snapshot đã gửi: Sample201 FP -> UNKNOWN, Sample202
TP giữ nguyên (NOT_CHECKED), Sample203 UNKNOWN giữ nguyên (NOT_CHECKED).
Chưa chạy full pipeline với Ollama/Joern trong môi trường của người dùng.
