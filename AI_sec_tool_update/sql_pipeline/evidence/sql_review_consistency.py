"""Flag a SQL review for human attention when its verdict conflicts with verified Java evidence."""

from .sql_path_presentation import verified_argument


VERSION = "sql-review-consistency-v1"
PROOF_ROLES = {
    "constant_sql_text": "constant_expression",
    "fixed_sql_alternatives": "fixed_values_from_branches",
    "request_independent_sql_text": "bytes_to_string",
}


def check_review(row, assessment):
    alert = row["alert"]
    result = {"version": VERSION, "status": "NO_CONFLICT_FLAGGED"}
    if alert.get("cwe") != "CWE-89" or assessment["verdict"] != "LIKELY_TP":
        return result

    selected = row.get("selected_evidence") or {}
    argument = verified_argument(selected, selected.get("jdbc_value_evidence"), alert)
    if not argument or (proof_role := PROOF_ROLES.get(argument["status"])) is None:
        return result

    code = {file["file_id"]: file["lines"] for file in (row["source"], *row["helpers"])}

    def has_source(ref):
        lines = code.get(ref.get("file_id"), [])
        line = ref.get("line")
        return type(line) is int and 1 <= line <= len(lines) and bool(lines[line - 1].strip())

    call = argument["call"]
    sql_argument = argument["sql_argument"]
    if type(call.get("column")) is not int or call["column"] < 1 or not all(map(has_source, (call, sql_argument))):
        return result
    references = [fact for fact in argument.get("evidence", []) if fact.get("role") == proof_role and has_source(fact)]
    if not references:
        return result

    return {
        "version": VERSION,
        "status": "REVIEW_REQUIRED",
        "reason": "likely_tp_conflicts_with_request_independent_sql_text",
        "model_verdict": assessment["verdict"],
        "java_evidence": {
            "status": argument["status"],
            "scope": selected["jdbc_value_evidence"]["scope"],
            "call": call,
            "sql_argument": sql_argument,
            "references": references,
        },
    }
