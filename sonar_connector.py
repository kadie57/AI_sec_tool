import requests
import json
import subprocess
import time

# --- CẤU HÌNH SONARQUBE CỦA BẠN ---
SONAR_URL = "http://localhost:9000"
PROJECT_KEY = "my_project_key" # Đổi thành Tên Project Key của bạn trên SonarQube
SONAR_TOKEN = "your_sqa_token_here" # Đổi thành Token bạn tạo trên SonarQube

def run_sonar_scanner(project_dir):
    """
    (Tùy chọn) Chạy SonarScanner dưới local để quét thư mục code.
    Nếu bạn quét bằng công cụ khác thì có thể bỏ qua hàm này.
    """
    print(f"[*] Đang khởi chạy SonarScanner cho thư mục: {project_dir}...")
    # Lệnh chạy SonarScanner (cần cấu hình sonar-project.properties trong thư mục code)
    cmd = ["sonar-scanner"]
    try:
        subprocess.run(cmd, cwd=project_dir, check=True)
        print("[+] Quét SonarQube thành công! Đợi 5s để server xử lý kết quả...")
        time.sleep(5)
    except Exception as e:
        print(f"[-] Lỗi khi chạy SonarScanner: {e}")

def fetch_issues_from_api():
    """
    Kết nối vào API của SonarQube để tải danh sách lỗ hổng về 
    và lưu thành file issues.json
    """
    print(f"[*] Đang tải danh sách lỗi từ SonarQube (Dự án: {PROJECT_KEY})...")
    
    url = f"{SONAR_URL}/api/issues/search"
    
    # Các tham số để lọc (Chỉ lấy lỗi đang OPEN và thuộc loại VULNERABILITY/BUG)
    params = {
        "componentKeys": PROJECT_KEY,
        "statuses": "OPEN",
        "types": "VULNERABILITY,BUG,CODE_SMELL" 
    }
    
    try:
        # Gửi request với Basic Auth (Token)
        response = requests.get(url, params=params, auth=(SONAR_TOKEN, ""))
        
        if response.status_code == 200:
            data = response.json()
            
            # Lưu ra file issues.json để các module sau đọc
            with open("issues.json", "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
                
            total_issues = data.get("total", 0)
            print(f"[+] Đã tải và lưu thành công {total_issues} lỗi vào file issues.json!")
            return True
        else:
            print(f"[-] Lỗi API SonarQube: Mã {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[-] Lỗi kết nối tới SonarQube: {e}")
        return False

if __name__ == "__main__":
    # Test thử độc lập file này
    fetch_issues_from_api()
