import json
import requests

def ask_ollama_zero_shot(source_code):
    prompt = f"""Bạn là một chuyên gia bảo mật. Hãy đọc đoạn mã nguồn dưới đây và cho biết nó có chứa lỗ hổng bảo mật nào không? Hãy chỉ ra vị trí và giải thích.

Mã nguồn:
```java
{source_code}
```
"""
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "qwen2.5-coder:1.5b",
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1}
    }
    try:
        response = requests.post(url, json=payload)
        return response.json().get('response', '')
    except Exception as e:
        return f"Lỗi: {e}"

def run_baseline():
    print("="*60)
    print("🧪 CHẠY THỬ NGHIỆM BASELINE (CHỈ DÙNG LLM THÔ, KHÔNG CÓ CPG)")
    print("="*60)
    
    try:
        with open("issues.json", "r") as f:
            data = json.load(f)
            issues = data.get("issues", []) if isinstance(data, dict) else data
    except Exception:
        print("[-] Không tìm thấy file issues.json.")
        return

    target_issues = [i for i in issues if i.get("rule") != "java:S106" and i.get("rule") != "java:S1220"]
    
    if not target_issues:
        print("[-] Không có lỗi rủi ro cao nào để thử nghiệm.")
        return
        
    issue = target_issues[0]
    file_path = issue.get("component")
    if ":" in file_path: file_path = file_path.split(":")[-1]
    
    print(f"[*] Đang test mã nguồn thô của file: {file_path}")
    
    try:
        with open(file_path, "r") as f: 
            raw_code = f.read()
    except Exception as e:
        print(f"[-] Lỗi đọc file: {e}")
        return
        
    print("[*] Đang gửi Code thô cho AI phân tích (Zero-shot)...")
    result = ask_ollama_zero_shot(raw_code)
    
    print("\n[ KẾT QUẢ TỪ LLM (BASELINE) ]")
    print(result)

if __name__ == "__main__":
    run_baseline()
