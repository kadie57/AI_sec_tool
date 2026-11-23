import json

def parse_issues(json_filepath):
    parsed_data = []
    try:
        with open(json_filepath, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
            issues = raw_data.get('issues', [])
            
            for issue in issues:
                parsed_issue = {
                    "rule": issue.get('rule'),
                    "file_path": issue.get('component'),
                    "line": issue.get('line', 0)
                }
                parsed_data.append(parsed_issue)
        return parsed_data
    except Exception as e:
        print(f"[-] Lỗi Parse file JSON: {e}")
        return []
