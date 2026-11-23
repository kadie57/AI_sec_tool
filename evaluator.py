import json
import os

def calculate_metrics(ai_results_file, ground_truth_file):
    print("="*60)
    print("📊 MODULE ĐÁNH GIÁ ĐỘ CHÍNH XÁC (EVALUATION PIPELINE)")
    print("="*60)

    try:
        with open(ai_results_file, 'r') as f:
            ai_data = json.load(f)
        with open(ground_truth_file, 'r') as f:
            truth_data = json.load(f)
    except Exception as e:
        print(f"[-] Lỗi đọc file: {e}")
        return

    TP = 0
    FP = 0
    TN = 0
    FN = 0

    for result in ai_data:
        file_name = result['file_name'].split('/')[-1]
        ai_predict = result['is_vulnerable_ai']
        
        actual_truth = truth_data.get(file_name, False)

        if ai_predict == True and actual_truth == True:
            TP += 1
        elif ai_predict == True and actual_truth == False:
            FP += 1
        elif ai_predict == False and actual_truth == False:
            TN += 1
        elif ai_predict == False and actual_truth == True:
            FN += 1

    total = TP + FP + TN + FN
    if total == 0:
        print("[-] Không có dữ liệu để đánh giá.")
        return

    accuracy = ((TP + TN) / total) * 100
    original_fp = FP + TN 
    fp_reduction = (TN / original_fp) * 100 if original_fp > 0 else 0

    print(f"[+] Tổng số cảnh báo đã phân tích: {total}\n")
    print("--- MA TRẬN NHẦM LẪN (CONFUSION MATRIX) ---")
    print(f"✔️ True Positives (Bắt đúng bệnh)       : {TP}")
    print(f"✔️ True Negatives (Lọc đúng cảnh báo giả): {TN}")
    print(f"❌ False Positives (Báo động nhầm)      : {FP}")
    print(f"❌ False Negatives (Bỏ sót lỗi)         : {FN}\n")

    print("--- BÁO CÁO KẾT QUẢ KHOA HỌC ---")
    print(f"🎯 Độ chính xác tổng thể (Accuracy)      : {accuracy:.2f}%")
    print(f"🛡️ Tỷ lệ giảm cảnh báo giả (FPR Reduction): {fp_reduction:.2f}%")
    print("="*60)

if __name__ == "__main__":
    if not os.path.exists("ground_truth.json"):
        mock_ground_truth = {
            "VulnerablePath.java": True,
            "SafePath.java": False
        }
        with open("ground_truth.json", "w") as f:
            json.dump(mock_ground_truth, f, indent=4)

    if os.path.exists("ai_results.json"):
        calculate_metrics("ai_results.json", "ground_truth.json")
    else:
        print("[-] Không tìm thấy file ai_results.json. Hãy chạy master_pipeline.py trước.")
