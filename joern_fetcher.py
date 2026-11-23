import os
import subprocess

# BỘ ĐỊNH TUYẾN JOERN (Dịch mã lỗi SonarQube thành lệnh tìm Source/Sink của Joern)
joern_router = {
    "java:S3649": { # SQL Injection
        "source": 'cpg.call.name("getParameter")',
        "sink": 'cpg.call.name("executeQuery").argument'
    },
    "java:S1874": { # Command Injection
        "source": 'cpg.call.name("getParameter")',
        "sink": 'cpg.call.name("exec").argument'
    },
    "java:S2083": { # Path Traversal
        "source": 'cpg.call.name("getParameter")',
        "sink": 'cpg.call.name("FileReader").argument'
    }
}

def fetch_source_code(file_path, error_line, context_lines=5):
    """Mở file Java thật để lấy đoạn code bị lỗi làm ngữ cảnh cho AI"""
    clean_path = file_path.split(':')[-1] if ':' in file_path else file_path
    
    if not os.path.exists(clean_path):
        return f"// Không tìm thấy file mã nguồn tại: {clean_path}"
        
    try:
        with open(clean_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            start = max(0, error_line - 1 - context_lines)
            end = min(len(lines), error_line + context_lines)
            return "".join(lines[start:end])
    except Exception as e:
        return f"// Lỗi khi fetch code: {e}"

def fetch_cpg_slice(file_path, rule_id):
    """
    Sử dụng công cụ Joern (qua Docker) để cắt luồng dữ liệu (Data-flow).
    """
    clean_path = file_path.split(':')[-1] if ':' in file_path else file_path
    
    # Nếu mã lỗi không có trong Router (không định nghĩa được source/sink), bỏ qua
    if rule_id not in joern_router:
        return f"Không thể trích xuất CPG cho mã lỗi {rule_id} vì chưa được định nghĩa trong joern_router."

    sink_cmd = joern_router[rule_id]["sink"]
    source_cmd = joern_router[rule_id]["source"]
    
    joern_script = f"""importCode("{clean_path}")\ndef sink = {sink_cmd}\ndef source = {source_cmd}\nsink.reachableByFlows(source).p"""
    
    script_name = "auto_slice.sc"
    with open(script_name, "w") as f:
        f.write(joern_script)
    
    print(f"   => [Joern] Đang tiến hành phân tích Data-flow (CPG) cho file: {clean_path}...")
    
    cmd = [
        "docker", "run", "--rm", "-v", f"{os.getcwd()}:/workspace", "-w", "/workspace", 
        "ghcr.io/joernio/joern:nightly", "joern", "--script", script_name
    ]
    
    # Thực thi lệnh Docker gọi Joern
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Xóa file script tạm sau khi chạy xong
    if os.path.exists(script_name): 
        os.remove(script_name)
    
    # --- BỘ LỌC RÁC JOERN CỦA BẠN ---
    clean_slice = []
    for line in result.stdout.split('\n'):
        if line.startswith('[INFO') or line.startswith('===') or 'Invoking CPG' in line or 'memory issues' in line or line.strip().startswith('1)') or line.strip().startswith('2)') or line.strip().startswith('3)'):
            continue
        if line.strip():
            clean_slice.append(line)
            
    # Nếu kết quả rỗng (không tìm thấy đường đi của dữ liệu)
    if not clean_slice:
        return "Joern phân tích xong: Không tìm thấy luồng dữ liệu nguy hiểm nào từ Nguồn tới Đích."
        
    return '\n'.join(clean_slice)
