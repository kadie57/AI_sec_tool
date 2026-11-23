# Giải thích tổng hợp SQL v2

Sửa lỗi mất thông tin trong replay_source_merge.merge_assessments.
- Kết luận được diễn giải theo decision_basis thực tế sau khi ghép nguồn.
- Không đưa nhận định nguồn cũ đã bị sửa vào phần kết luận cuối.
- Giữ nguyên văn giải thích từng bước ở các trường *_explanation_original.
- Thêm nguyên văn dòng mã bằng Python, từ source snapshot, không nhờ AI chép lại.
- Giữ nguyên prompt, mô hình, quy tắc nhãn, missing_context và yêu cầu thẩm định.
- Đổi version adapter để nhận diện bản sửa; router còn kiểm tra hash dependency.

Đây là sửa phép ghép và truy vết, KHÔNG phải huấn luyện hay cải thiện suy luận mô hình.
Không tự sửa dòng bằng chứng chưa sát nghĩa hoặc lời giải thích sai trong artifact gốc.
Phần kết luận là diễn giải xác định của các trạng thái AI báo cáo; dòng mã giúp đối chiếu
cơ chế cụ thể. Giải thích chi tiết bước 2 vẫn được UI hiển thị riêng kèm cảnh báo khi bị sửa.

Cài các file trong ZIP vào ~/AI_sec_tool sau khi sao lưu những file trùng tên.
Các file không sửa được giữ nguyên theo ZIP người dùng cung cấp.
Chạy kiểm tra:
    python3 test_explanation_merge.py
    python3 master_pipeline_multi_v1.py --check

Replay chỉ đọc artifact đã lưu, không gọi dịch vụ, không sửa run hoặc thẩm định cũ:
    python3 replay_explanation_v2.py --run RUN_A --run RUN_B --sample Trial07.java --sample Trial04.java --sample Trial06.java

RUN_A là lượt chỉ Trial07; RUN_B là lượt ba mẫu Trial01/04/06. Cần thư mục run đầy đủ
(manifest, ai_results, source.java.txt, llm_stage2.json, llm_source_audit.json).
Script dừng nếu hash, dòng, mã nguồn trong request hoặc nhãn ghép không khớp.
Kết quả mới ở experiments/explanation_merge_v2, không tự xuất hiện như run mới trên UI.
Replay này kiểm chứng phép ghép, không phải lượt đánh giá độc lập chất lượng AI.
Lượt pipeline mới sau khi cài đặt tự sử dụng phép ghép mới và vẫn gọi AI như trước.
