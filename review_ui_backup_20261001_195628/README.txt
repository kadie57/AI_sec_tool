Đặt thư mục review_ui trong /home/khanh/AI_sec_tool.
Chạy:
cd ~/AI_sec_tool
source .venv_review_ui/bin/activate
python review_ui/app.py
Mở http://127.0.0.1:5050
Dừng bằng Ctrl+C ở terminal.
Bản đầu chỉ đọc hai thư mục runs và eval_sql89_new_v1/runs.
Không import pipeline, không quét, không gọi AI, không ghi kết quả.
Mỗi request đọc lại JSON; nếu lượt đang ghi hoặc file lỗi, tải lại trang.
Chưa có chi tiết mã nguồn hoặc chức năng ghi thẩm định.
