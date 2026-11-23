# Đối chiếu lượt kiểm tra nguồn SQL ngày 23/11/2026

## Phạm vi

Tám cảnh báo SQL đã từng bị chặn bởi giới hạn kích thước được chạy lại kiểm tra nguồn. Lượt mới tái sử dụng kết quả phân tích SQL trước đó, lưu 12 lần sinh nguồn với tổng thời gian các lần sinh khoảng 22 phút 31 giây. Không phải lượt đánh giá lại cả 49 cảnh báo được hỗ trợ.

Kết quả tải lên: **1 LIKELY_FP, 5 LIKELY_TP, 2 UNKNOWN**; hai UNKNOWN đều do bằng chứng nguồn chưa hợp lệ. Sáu kết luận TP/FP khớp nhãn tham chiếu của đúng commit OWASP. Điều này chỉ nói về nhãn trên sáu mẫu đã có kết luận; không chứng minh sáu lập luận đều đúng hoặc hệ thống đạt độ chính xác 100%.

Nhãn tham chiếu đối chiếu ngoại tuyến: `a452b3aafd232245d0753e54eb243d6651f8ef96`, CSV SHA-256 `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`. Các script suy luận và ghép kết quả không đọc nhãn tham chiếu này.

## Từng mẫu

| Mẫu | Nhãn OWASP | Kết quả tải lên | Sau sửa chính sách ghép | Nhận xét mã nguồn và bằng chứng |
|---|---|---|---|---|
| 00999 | Không có lỗ hổng mục tiêu | LIKELY_FP | LIKELY_FP | Điều kiện `(7 * 42) - 86 > 200` đúng; helper trả hằng. Mục thiếu về nguồn của `param` đã có cookie tại dòng 61. Tuy vậy, lời giải thích nguồn nói giá trị cookie được dùng trong SQL chưa mô tả đúng việc bị ghi đè bằng hằng. |
| 01093 | Có lỗ hổng mục tiêu | LIKELY_TP | LIKELY_TP | Header được đọc tại dòng 45; helper đưa giá trị vào map rồi lấy đúng key ra để ghép SQL. Bằng chứng nguồn và vị trí SQL phù hợp. |
| 01311 | Có lỗ hổng mục tiêu | LIKELY_TP | LIKELY_TP | Nhánh số nguyên đi tới `bar = param`; nhận định TP phù hợp code. Nhưng source_evidence ghi dòng 33, trong khi thao tác đọc parameter ở dòng 43; dòng 43 chỉ xuất hiện trong flow_evidence. |
| 01558 | Có lỗ hổng mục tiêu | LIKELY_TP | LIKELY_TP | `charAt(2)` chọn nhánh C truyền `param`. Đầu vào đến qua `SeparateClassRequest.getTheParameter` ở dòng 45; mô hình nói đó là HttpServletRequest.getParameter dù chưa có mã wrapper trong ngữ cảnh. Nhãn khớp nhưng nguồn chưa được chứng minh đầy đủ từ phần mã đã gửi. |
| 02088 | Có lỗ hổng mục tiêu | UNKNOWN | UNKNOWN | Cả hai lần source audit dẫn dòng 45 trống. Bước SQL giữ UNRESOLVED và thiếu nội dung helper; bên trong có ThingFactory/ThingInterface ngoài tệp. |
| 02093 | Không có lỗ hổng mục tiêu | UNKNOWN | UNKNOWN | Hai lần source audit dẫn dòng 45 trống. Bước SQL cũ vẫn báo CHANGEABLE dù `"ABC".charAt(1)` chọn nhánh B, gán `bar = "bob"`. Cần sửa suy luận, không tính UNKNOWN do lỗi dẫn dòng là đã sửa đúng lỗi SQL. |
| 02171 | Có lỗ hổng mục tiêu | LIKELY_TP | LIKELY_TP | Mã hóa rồi giải mã Base64 không đóng vai trò bind SQL; giá trị vẫn ghép vào phần password. Sau sửa có đúng vị trí SQL dòng 54. Nguồn dẫn cả dòng 33 không thích hợp và dòng 43 có thao tác đọc đúng. |
| 02186 | Có lỗ hổng mục tiêu | LIKELY_TP | UNKNOWN | Source audit xóa nhầm yêu cầu xem doSomething/ThingFactory/ThingInterface chỉ vì nhận diện HTTP. Dòng đọc HTTP còn bị dẫn là 33 thay vì 43. Chính sách mới giữ lại thiếu sót helper; SQL effect vẫn là dữ liệu cũ, chưa được phân tích lại. |

## Ý nghĩa của bản sửa

Bản sửa được áp dụng đồng nhất theo cấu trúc đầu ra và dạng câu hỏi nguồn, không gắn nhãn theo tên mẫu hoặc theo OWASP. Nó đưa 02186 về UNKNOWN vì bằng chứng hiện có chưa giải quyết mục thiếu đã nêu. Kết quả ghép mới là **4 LIKELY_TP, 1 LIKELY_FP, 3 UNKNOWN**, gồm hai lỗi kiểm tra nguồn và một trường hợp thiếu ngữ cảnh.

Không dùng con số năm kết luận khớp nhãn để khẳng định mọi lời giải thích đã đáng tin cậy. Ví dụ 01558 vẫn cần mã wrapper và 01311 cần dẫn đúng dòng nguồn. Bản sửa này chỉ khắc phục việc bỏ nhầm thiếu sót trong phép ghép và làm rõ lỗi dòng cho lần sửa sau.

## Thứ tự xử lý tiếp

1. Bổ sung ngữ cảnh của helper/wrapper liên quan từ cùng phiên bản mã nguồn, có hash và đường dẫn; không đưa nhãn tham chiếu vào yêu cầu AI.
2. Phân tích lại giá trị thực tới SQL, gồm nhánh switch và đường qua helper; không tiếp tục kế thừa SQL effect cũ ở các ca đó.
3. Ràng buộc và kiểm tra tốt hơn bằng chứng nguồn, phân biệt đúng dòng đọc đầu vào với một dòng mã bất kỳ.
4. Sau khi đóng cấu hình, đánh giá lại cùng phạm vi và so sánh với baseline. Các sửa đổi đã dựa trên tám mẫu này nên phải trình bày chúng là kiểm tra sau sửa, không gọi là holdout mới.
