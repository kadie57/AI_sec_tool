"""Explicit rule registry for the initial JDBC SQL-injection scope.

Unknown rules are NOT classified as code smells. Metadata from the actual
SonarQube installation is retained by the pipeline for subsequent review.
"""
MAPPING_VERSION = "sql89-v2"
SONAR_TO_CWE = {
    "java:S3649": {
        "cwe_id": "CWE-89", "name": "SQL Injection",
        "supported": True, "mapping_source": "SonarSource java:S3649",
    },
    "findbugs:SQL_INJECTION_JDBC": {
        "cwe_id": "CWE-89", "name": "SQL Injection in JDBC",
        "supported": True,
        "mapping_source": "https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC",
    },
    "findsecbugs:SQL_INJECTION_JDBC": {
        "cwe_id": "CWE-89", "name": "SQL Injection in JDBC",
        "supported": True,
        "mapping_source": "https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC",
    },
    "java:S2083": {
        "cwe_id": "CWE-22", "name": "Path Traversal",
        "supported": False, "mapping_source": "SonarSource java:S2083",
    },
    "java:S6437": {
        "cwe_id": "CWE-798", "name": "Hard-coded credentials",
        "supported": False, "mapping_source": "SonarSource java:S6437",
    },
}


def get_cwe_info(sonar_rule_id):
    if sonar_rule_id == "java:S1874":
        return {"cwe_id": None, "name": "Deprecated API usage",
                "supported": False, "mapping_source": "SonarSource java:S1874",
                "reason": "Quy tắc API lỗi thời, không phải Command Injection."}
    if sonar_rule_id == "java:S2095":
        return {"cwe_id": None, "name": "Resources should be closed",
                "supported": False, "mapping_source": "SonarSource java:S2095",
                "reason": "Đóng tài nguyên nằm ngoài phạm vi SQL Injection."}
    result = SONAR_TO_CWE.get(sonar_rule_id)
    if result:
        return {**result, "reason": "" if result["supported"] else "Ngoài phạm vi hiện tại."}
    return {"cwe_id": None, "name": "Unmapped rule", "supported": False,
            "mapping_source": None,
            "reason": "Chưa xác minh ánh xạ rule; không suy ra đây là Code Smell."}
