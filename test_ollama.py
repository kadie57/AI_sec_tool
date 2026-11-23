import requests
import json

def test_local_ai():
    url = "http://localhost:11434/api/generate"
    
    # Payload gửi lên Ollama
    payload = {
        "model": "qwen2.5-coder:1.5b",
        "prompt": "Bạn là chuyên gia bảo mật. Hãy giải thích ngắn gọn lỗi SQL Injection là gì trong 2 câu.",
        "stream": False
    }
    
    print("Đang gửi yêu cầu lên Ollama Local... Vui lòng đợi vài giây...")
    
    try:
        response = requests.post(url, json=payload)
        response_data = response.json()
        
        print("\n--- KẾT QUẢ TỪ AI ---")
        print(response_data.get('response', 'Không có câu trả lời'))
        
    except Exception as e:
        print(f"Lỗi kết nối: {e}")

if __name__ == "__main__":
    test_local_ai()
