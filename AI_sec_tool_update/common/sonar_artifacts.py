"""Find source files and warning coordinates in recorded SonarQube data."""

from pathlib import Path


def resolve_issue_path(issue, project, root):
    component = issue.get("component", "")
    prefix = project + ":"
    if not component.startswith(prefix):
        raise ValueError("Component không thuộc project đã cấu hình.")
    relative = Path(component[len(prefix):])
    if relative.is_absolute():
        raise ValueError("Đường dẫn component phải tương đối.")
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()) or candidate.suffix != ".java":
        raise ValueError("Component không phải file Java trong project.")
    if not candidate.is_file():
        raise ValueError("Không tìm thấy file của cảnh báo.")
    return candidate


def issue_range(issue):
    span = issue.get("textRange") or {}
    start = span.get("startLine", issue.get("line"))
    end = span.get("endLine", start)
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise ValueError("Cảnh báo thiếu vùng dòng hợp lệ.")
    return start, end
