# Bộ mẫu đã dùng trong khóa luận

Thư mục này tập hợp bản sao mã Java, danh sách ca, cảnh báo đã lưu và nhãn tham chiếu. Đường dẫn bên trong từng snapshot được giữ theo manifest để đối chiếu lại hash và vùng dòng. Kết quả Joern, Qwen và báo cáo từng lượt nằm ở thư mục `runs/` tương ứng.

| Bộ mẫu | Nội dung | Nguồn gốc |
|---|---|---|
| [`legacy/`](legacy/) | 29 tệp Java trong `Clean_Code`, 6 ca `Probe21`–`Probe26` của SQL Injection và 3 biến thể vá `PathCase01`. Kèm nhãn đã lưu của các đợt có nhãn. | `Clean_Code`, `eval_followup_v1`, `eval_sql89_new_v1`, `path_patch_sonar_1105` và `path_patch_refine_1105` trong archive `2026-11-25-repo-split`. |
| [`owasp/`](owasp/) | 66 mẫu riêng biệt. Bộ holdout gồm 20 SQL Injection, 20 Path Traversal và 20 Command Injection. Bộ tương thích gồm 6 mẫu. Các nhóm SQL8, SQL12 và SQL-positive3 có danh sách riêng và dùng chung mã nguồn đã lưu. | Các collection `owasp-holdout-20261115T151839Z-b04660`, `owasp-compat-20261114T045846Z-8508c7`, fixture SQL8 và các lượt chọn mẫu đã lưu. |
| [`juliet/`](juliet/) | Pilot gồm 8 tệp mẫu. Holdout gồm 12 tệp Java thuộc 8 ca, với 20 cảnh báo SonarQube đã đối chiếu nhãn. Hai bộ dùng chung 10 tệp `testcasesupport`. | `runs/juliet-cwe89-pilot-20261124`, `runs/juliet-cwe89-sonarqube-20261124` và `runs/juliet-cwe89-holdout-20261124`. |
| [`controls/`](controls/) | Bộ Java tổng hợp ba tệp dùng để so CPG theo cảnh báo với CPG toàn snapshot, cùng một tệp gồm 4 điểm đối chứng sinh đặc tả nguồn. | `fixtures/project_sql3`, `fixtures/source_specs` và nhãn đã lưu của hai thực nghiệm. |

Hai lượt Juliet pilot dùng cùng một snapshot Java. Các collection `reference-only`, `findsecbugs` và `sonarqube` lưu ba nguồn cảnh báo riêng. Bộ đối chứng ba tệp dùng nhãn và tọa độ lập trước trên mã tổng hợp.

[`owasp/used-samples.json`](owasp/used-samples.json) liệt kê mã mẫu trong hai collection OWASP đã lưu. [`owasp/expectedresults-used.csv`](owasp/expectedresults-used.csv) trích nhãn chính thức cho các mã đó. Khi lập tập OWASP mới, có thể dùng danh sách mã để loại các ca đã xuất hiện trong hai collection này. Nhãn tham chiếu dùng để chấm kết quả sau khi chạy.

Chạy từ `AI_sec_tool_update/` để kiểm tra bản sao SQL8 và Juliet holdout.

```bash
python3 prepare_sql_evidence.py \
  --from-run datasets/owasp/splits/sql8 \
  --source-root datasets/owasp/sources \
  --recorded-joern datasets/owasp/splits/sql8/joern --check

python3 prepare_sql_evidence.py \
  --from-run datasets/juliet/holdout/collections/sonarqube \
  --source-root datasets/juliet/sources --check
```

Kiểm tra toàn bộ bản sao từ thư mục `datasets/` bằng `sha256sum -c SHA256SUMS`. [`inventory.json`](inventory.json) ghi số tệp, ca và cảnh báo theo bộ.
