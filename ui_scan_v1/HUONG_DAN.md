# Thêm quét SonarQube vào giao diện — ui_scan_v1

## Mục đích

Bạn đã chạy AI từ lượt cảnh báo đã lưu, thẩm định Sample101 và xuất CSV.
Bản này bổ sung điểm bắt đầu của quy trình: **quét mã nguồn ngay trong giao diện**.

Luồng sử dụng: Quét SonarQube → chọn file → AI kiểm chứng → xem bằng chứng →
lưu thẩm định → xuất CSV. Đây là kiểm chứng cảnh báo SonarQube; chưa phải
chạy thử khai thác lỗ hổng hay chứng minh chương trình an toàn tuyệt đối.

## Cài trên Ubuntu

Áp dụng cho source ZIP ngày 28/10/2026 sau khi đã cài `ui_analysis_v1`.
Trình cài kiểm tra hash các file hiện có và tự sao lưu trước khi cập nhật.
Nếu file khác, trình cài dừng để tránh ghi đè thay đổi của bạn.

1. Chờ tác vụ UI đang chạy hoàn tất. Dừng Flask bằng Ctrl+C ở terminal mở UI.
2. Giải nén ZIP để có `~/AI_sec_tool/ui_scan_v1/install.py`.
3. Từ thư mục dự án, chạy:

```bash
cd ~/AI_sec_tool
python3 ui_scan_v1/install.py
```

Nếu có `INSTALL_OK`, mở lại:

```bash
docker start sonarqube-db sonarqube
source .venv_review_ui/bin/activate
python review_ui/app.py
```

Mở http://127.0.0.1:5050. Không cần bật Ollama để chỉ quét SonarQube.
Gói này dùng các thư viện Flask và requests đã dùng ở bản UI trước.

## Lượt đầu tiên

1. Bấm **Quét SonarQube mới**.
2. Giữ project key `project_1`. Việc này cập nhật lượt phân tích của dự án đó
   trên SonarQube và dùng bộ quy tắc hiện đã cấu hình.
3. Nhập token trong ô mật khẩu nếu ứng dụng chưa có SONAR_TOKEN.
   Token chỉ truyền cho tiến trình quét, không ghi vào bản ghi tác vụ/nhật ký.
4. Bấm **Bắt đầu quét SonarQube**. Không sửa mã trong lúc quét; không chạy
   một lượt quét khác cùng project từ terminal.
5. Khi thấy **Đã lấy cảnh báo SonarQube — chưa gọi AI**, kiểm tra số cảnh báo
   SQL, Path và Command. Gửi phần tổng kết này để đối chiếu lượt quét.

Chưa cần phân tích lại Sample101. Với lượt tiếp theo muốn kiểm chứng, bấm
**Chọn file để AI kiểm chứng**; chọn file cần xử lý rồi kiểm tra cấu hình/chạy AI.
Bước AI mới cần Docker/Joern và Ollama. Các baseline SQL cũ vẫn cần tồn tại.

## Cấu hình và xử lý lỗi

- Thư mục quét cố định là `Clean_Code`, toàn bộ file Java bên dưới được biên dịch.
- Máy chủ mặc định: `http://127.0.0.1:9000`; có thể đặt SONAR_URL trước khi mở UI.
- Scanner dùng SONAR_SCANNER_PATH nếu đã đặt, nếu không dùng đường dẫn cũ:
  `/home/khanh/Downloads/sonar-scanner-8.0.1.6346-linux-x64/bin/sonar-scanner`.
- Nếu SonarQube đang khởi động hoặc token không hợp lệ, nhật ký sẽ báo lỗi.
  Chờ SonarQube sẵn sàng hoặc sửa token rồi bắt đầu lượt quét mới.
- Không có cảnh báo thuộc ba nhánh hỗ trợ: kiểm tra Quality Profile/FindSecBugs.
  Không dùng kết quả đó để kết luận mọi file an toàn.
- Quét thất bại không tự gọi AI. Lỗi biên dịch/scanner được đưa vào nhật ký UI.
- Mất tab không dừng tiến trình. Tắt máy có thể ngắt tiến trình; bản này không
  tự tiếp tục một lượt quét bị ngắt, hãy xem nhật ký trước khi quét mới.

## Phạm vi và kiểm tra đã thực hiện

Bản cập nhật thêm trang quét, tiến trình nền, nhật ký, thống kê cảnh báo theo
ba nhánh và nút chuyển sang phân tích. Adapter chỉ gọi bộ thu thập hiện có
ở chế độ collect-only; không chỉnh file analyzer gốc hoặc prompt AI.
Kết quả và lịch sử thẩm định cũ không bị sửa.

Đã qua 14 kiểm tra tự động offline: quét → chọn cảnh báo, khóa tác vụ chung,
không lưu token, CSRF, các trạng thái lỗi, quét không có cảnh báo hỗ trợ,
phân loại inventory của collector gốc, phát hiện mã nguồn thay đổi trong
lúc quét, cùng kiểm tra hồi quy thẩm định/CSV. Công cụ quét và API SonarQube
được mô phỏng trong kiểm tra; cần xác nhận kết nối thật trên laptop của bạn.

Chạy lại kiểm tra offline khi cần:

```bash
cd ~/AI_sec_tool
source .venv_review_ui/bin/activate
python -m unittest discover -s ui_scan_v1 -p 'test_ui_*.py' -v
```

Giới hạn còn lại: chỉ Java trong Clean_Code, các rule đã liệt kê trong router;
không lấy Security Hotspots; không xác thực nhiều người dùng; chỉ mở localhost.
AI và cơ chế thẩm định giữ nguyên như bản trước. Tính năng này không phải
huấn luyện hay đo độ chính xác mới của mô hình.
