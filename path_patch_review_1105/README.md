# Đối chiếu bản sửa PathCase01 — 05/11/2026

## Kết luận

Chức năng tạo bản sửa đã nhận được một bản nháp thực từ Qwen 14B. Hash nguồn và diff trong JSON khớp mã gốc. Bản AI biên dịch được và đạt 12 tình huống kiểm tra chức năng/đường dẫn tĩnh. Tuy nhiên, chưa chấp nhận bản này theo chính giả định mà nó nêu: người không tin cậy có thể thay tệp hoặc symlink trong thư mục đọc.

Trong mô phỏng thay đổi có kiểm soát giữa bước kiểm tra và bước mở, bản AI vẫn đọc tệp ngoài thư mục gốc. Bản hiệu chỉnh trong gói dùng SecureDirectoryStream và NOFOLLOW_LINKS để mở từng thành phần tương đối với directory handle; đã chặn hai tình huống thay thế được thử.

Đây là **gói kiểm chứng và bản hiệu chỉnh sau thẩm định**, không phải gói cài giao diện. Bản hiệu chỉnh do trợ lý viết sau khi kiểm tra, không phải kết quả nguyên bản của mô hình Qwen trên máy người dùng. Không huấn luyện lại mô hình, không sửa kết quả AI gốc và không áp dụng lên dự án.

## Kết quả đã quan sát

Môi trường kiểm tra của trợ lý: Linux, OpenJDK 17.0.20.

| Nhóm kiểm tra | Bản Qwen đề xuất | Bản hiệu chỉnh |
| --- | --- | --- |
| Biên dịch nguyên văn mã nguồn | Thành công | Thành công |
| 12 tình huống tĩnh/chức năng | Đạt 12/12 | Đạt 12/12 |
| Đổi tệp thành symlink sau kiểm tra, trước mở | Vẫn đọc dữ liệu ngoài base | Bị từ chối, không in dữ liệu |
| Đổi thư mục trung gian thành symlink sau kiểm tra, trước mở | Vẫn đọc dữ liệu ngoài base | Bị từ chối, không in dữ liệu |
| Quét lại SonarQube | Chưa thực hiện | Chưa thực hiện |

12 tình huống gồm: tệp thường, tệp trong thư mục con, `sub/../ok.txt` còn trong gốc, symlink nội bộ, tệp rỗng, byte đầu 255, traversal ra ngoài, thư mục anh em có cùng tiền tố tên, symlink tệp ra ngoài, symlink thư mục ra ngoài, tệp không tồn tại và sai số lượng đối số.

Hai phép thử thay thế **có chèn thao tác đổi fixture vào bản sao kiểm thử** ngay sau kiểm tra. Chúng chứng minh hậu quả của một thứ tự thao tác có thể xảy ra; không phải phép đo khai thác race tự nhiên hoặc tỷ lệ khai thác thành công ngoài thực tế. Tất cả dữ liệu bên ngoài base cũng chỉ là fixture do script tự tạo trong thư mục tạm.

## Những điểm cần sửa trong lời giải thích của AI

1. AI tự đưa ra giả định người dùng có quyền sửa thư mục/symlink, trong khi mã nguồn không chứng minh chính sách quyền này. Với giả định đó, `toRealPath()` rồi mở lại theo pathname chưa đủ giải quyết thay đổi xảy ra giữa hai bước.
2. `System.out.println(input.read())` in giá trị byte đầu dạng số nguyên (hoặc -1 nếu hết tệp), không phải in ký tự. Tệp bắt đầu bằng ASCII `A` in `65`.
3. Kế hoạch kiểm thử `../../etc/passwd` không chính xác như mô tả. Từ base literal `/var/www/uploads/`, hai lần `..` thường dẫn tới `/var/etc/passwd`; nếu tệp không tồn tại, `toRealPath()` có thể ném `NoSuchFileException` trước khi đến kiểm tra `startsWith`. Bộ thử dùng `../outside.txt` do chính script tạo để tránh phụ thuộc tệp hệ thống và phân biệt đúng lý do bị từ chối.

## Điều kiện áp dụng bản hiệu chỉnh

- Thư mục gốc được cấu hình và các thư mục cha phải do ứng dụng/quản trị viên tin cậy quản lý. Người không tin cậy không được thay chính điểm gắn thư mục gốc trong quá trình mở nó.
- Java filesystem provider phải hỗ trợ SecureDirectoryStream. Nếu không hỗ trợ, bản hiệu chỉnh dừng với lỗi; không chuyển sang cách mở yếu hơn.
- Symlink đã tồn tại trỏ vào trong base vẫn được phân giải và đọc trong các ca đã thử. Symlink trỏ ra ngoài bị chặn; thay thế symlink sau kiểm tra bị chặn khi mở bằng NOFOLLOW_LINKS.
- Không chứng minh tất cả tình huống race/quyền truy cập, nguồn gốc hard link hay phân quyền nghiệp vụ trên từng tệp. Chỉ ghi nhận đúng các phép thử đã thực hiện.
- Chưa quét lại SonarQube. Cảnh báo tĩnh còn hay mất không phải bằng chứng duy nhất về hiệu quả bản sửa.

## Chạy trên Ubuntu của bạn

Mục đích: xác nhận bản hiệu chỉnh hoạt động với Java và filesystem provider trên máy demo trước khi dùng trong dự án.

Giải nén gói vào `~/AI_sec_tool` rồi chạy:

```bash
cd ~/AI_sec_tool/path_patch_review_1105
python3 check_patch.py
```

Chỉ cần Python 3 và Java có compiler JDK; không cần AI, SonarQube, Flask hoặc quyền sudo. Không thay đổi `Clean_Code`, `runs`, quyền truy cập hệ thống hay `/var/www/uploads`. Mã được biên dịch nguyên văn để kiểm tra cú pháp; các bản chạy chức năng chỉ thay hằng đường dẫn base sang thư mục tạm. Hash khóa đúng ba bản nguồn đã kiểm tra, không nhận mã AI bất kỳ để thực thi.

Sau khi chạy, gửi `verification_results.json`. Kết quả tham chiếu từ môi trường của trợ lý nằm riêng trong `verification_results_reference.json`.

Nếu đạt, bước tiếp theo là đưa **bản hiệu chỉnh vào một bản sao dùng để kiểm chứng**, quét SonarQube và đối chiếu trước–sau. Chưa chép đè mẫu gốc: các mẫu gốc còn cần để tái hiện thực nghiệm khóa luận.

## Các file

- `proposal_original.json`: JSON Qwen người dùng đã gửi, giữ nguyên.
- `original.java.txt`: mã gốc đã đối chiếu hash.
- `proposed.java.txt`: mã Qwen đề xuất, giữ nguyên.
- `reviewed.java.txt`: bản hiệu chỉnh sau đánh giá.
- `PathCase01.reviewed.patch`: diff mã gốc → bản hiệu chỉnh, chưa áp dụng.
- `check_patch.py`: bộ kiểm chứng giới hạn cho đúng ba bản mã trên.
- `verification_results_reference.json`: kết quả quan sát trong môi trường trợ lý.

## Tài liệu đối chiếu

- Java Path API: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Path.html
- SecureDirectoryStream: https://docs.oracle.com/javase/8/docs/api/java/nio/file/SecureDirectoryStream.html
- CWE-367, thay đổi tài nguyên giữa kiểm tra và sử dụng: https://cwe.mitre.org/data/definitions/367.html

Khi trình bày khóa luận, tách rõ “đề xuất Qwen”, “kết quả kiểm tra” và “bản hiệu chỉnh sau thẩm định”. Không tính bản hiệu chỉnh thành một bản sửa tự động thành công của Qwen.
