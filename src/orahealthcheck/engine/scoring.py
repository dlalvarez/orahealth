from collections import Counter

from orahealthcheck.models import Result, ResultStatus

# Penalización por hallazgo de salud. ERROR no es un hallazgo de salud: no penaliza el
# puntaje; reduce la cobertura de evidencia.
STATUS_WEIGHTS = {"WARNING": 5, "FAIL": 15, "CRITICAL": 25}
DEFAULT_MIN_COVERAGE_PCT = 80


def summarize(results: list[Result], min_coverage_pct: float = DEFAULT_MIN_COVERAGE_PCT) -> dict[str, int | float | str | None]:
    """Resume resultados separando salud (puntaje) de completitud (cobertura).

    - ``score``: 100 menos penalizaciones por hallazgos, sobre checks evaluados; ``None``
      si no se evaluó ninguno (no hay base para un puntaje).
    - ``coverage_pct``: porcentaje de checks aplicables que se pudieron evaluar.
    - ``global_status``: ``ERROR`` si la cobertura es menor a ``min_coverage_pct``
      (evaluación no concluyente); si no, el peor estado de salud observado.
    """
    counts = Counter(result.status.value for result in results)
    applicable = len([r for r in results if r.status != ResultStatus.SKIPPED])
    evaluated = applicable - counts["ERROR"]
    penalty = sum(counts[status] * weight for status, weight in STATUS_WEIGHTS.items())
    if applicable == 0:
        score: int | None = 100
    elif evaluated == 0:
        score = None
    else:
        score = max(0, 100 - penalty)
    coverage = round(evaluated * 100 / applicable, 1) if applicable else 100.0

    if applicable and coverage < min_coverage_pct:
        global_status = "ERROR"
    elif counts["CRITICAL"]:
        global_status = "CRITICAL"
    elif counts["FAIL"]:
        global_status = "FAIL"
    elif counts["WARNING"]:
        global_status = "WARNING"
    else:
        global_status = "PASS"
    return {
        "score": score,
        "global_status": global_status,
        "coverage_pct": coverage,
        "evaluated_checks": evaluated,
        "applicable_checks": applicable,
        **counts,
    }
