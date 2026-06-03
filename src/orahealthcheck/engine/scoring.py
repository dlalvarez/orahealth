from collections import Counter

from orahealthcheck.models import Result, ResultStatus


def summarize(results: list[Result]) -> dict[str, int | str]:
    counts = Counter(result.status.value for result in results)
    applicable = len([r for r in results if r.status != ResultStatus.SKIPPED])
    bad_weight = counts["WARNING"] * 5 + counts["FAIL"] * 15 + counts["CRITICAL"] * 25 + counts["ERROR"] * 10
    score = max(0, 100 - bad_weight) if applicable else 100
    global_status = "PASS"
    if counts["CRITICAL"] or counts["ERROR"]:
        global_status = "CRITICAL"
    elif counts["FAIL"]:
        global_status = "FAIL"
    elif counts["WARNING"]:
        global_status = "WARNING"
    return {"score": score, "global_status": global_status, **counts}
