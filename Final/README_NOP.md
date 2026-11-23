# AI_sec_tool — Mã nguồn nộp khóa luận

Thư mục này chứa mã thu thập cảnh báo SonarQube, bộ điều phối SQL Injection, Path Traversal và Command Injection, mã trích xuất và kiểm chứng bằng chứng, giao diện Flask, mã xuất báo cáo và các lệnh thực nghiệm OWASP. Các lệnh phân tích lại SQL là công cụ thực nghiệm riêng.

## Kiểm tra và mở giao diện

Dùng Python 3.12 trong môi trường ảo. Từ thư mục Final, chạy các lệnh sau.

    python -m pip install -r requirements.txt
    python -m unittest discover -s tests -v
    python -m unittest test_sql_fallback test_explanation_merge
    python scripts/ai_sec.py --help
    python scripts/ai_sec.py review

Giao diện mặc định mở tại http://127.0.0.1:5050. Dữ liệu sẽ hiển thị khi có các lượt chạy ở đúng thư mục mà giao diện đọc.

Kiểm tra trên bản nộp đạt 3 test launcher, 7 test SQL fallback và 3 test ghép giải thích. Bộ `test_pipeline.py` vẫn có hai lỗi đã ghi nhận ở bản gốc. Cả hai test chờ nhãn cụ thể khi bộ kiểm chứng trả `UNKNOWN`.

## Dữ liệu và dịch vụ để chạy thực nghiệm

Đợt nộp này tách mã nguồn khỏi các bộ mẫu Java, nhãn tham chiếu, cấu hình đóng băng và hồ sơ chạy. Đặt bộ mã Java cần quét ở Clean_Code/ rồi cấu hình SONAR_URL, SONAR_PROJECT_KEY, SONAR_SCANNER_PATH và SONAR_TOKEN cho môi trường chạy. Tiến trình lấy bằng chứng cần Java và Joern, còn phân tích bằng mô hình cần Ollama với đúng model và digest theo cấu hình.

Phân tích ba nhóm cần một lượt thu thập hợp lệ và mã nguồn khớp hash. Bộ kiểm tra cấu hình SQL còn đọc các artifact baseline đã chốt trong runs/20261001T024646Z-683d4b/ và experiments/. Một số lệnh tái lập còn yêu cầu checkout BenchmarkJava, kế hoạch, nhãn và hash của đúng phiên bản thực nghiệm. Các dữ liệu đó được quản lý riêng với gói mã nguồn.

Cấu trúc giữ các liên kết tương đối để tương thích với entry point và đường dẫn gốc. Khi chuyển thư mục, dùng cách sao chép giữ liên kết và giữ nguyên cấu trúc thư mục.
