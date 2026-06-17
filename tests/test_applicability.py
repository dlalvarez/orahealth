from orahealthcheck.engine.applicability import ApplicabilityEngine
from orahealthcheck.engine.scoring import summarize
from orahealthcheck.models import Check, Inventory, Target
from orahealthcheck.models.result import Result, ResultStatus


def test_non_matching_platform_is_skipped():
    target = Target("t1", "T1", "dev", "standalone", "p1", operating_system={"platform": "linux"})
    inventory = Inventory("t1", "standalone", "dev", operating_system={"platform": "linux"})
    check = Check("c1", "g1", "C1", applies_to={"platforms": ["aix"]})
    applies, reason = ApplicabilityEngine().evaluate(check, target, inventory)
    assert applies is False
    assert "plataforma" in reason


def test_required_feature_detected_allows_check():
    target = Target("t1", "T1", "dev", "standalone", "p1", operating_system={"platform": "linux"})
    inventory = Inventory(
        "t1",
        "standalone",
        "dev",
        features={"oracle_rac": {"detected": True, "status": "detected", "reason": "cluster_database = TRUE"}},
    )
    check = Check("c1", "g1", "C1", applicability={"requires_feature": "oracle_rac"})

    applies, reason = ApplicabilityEngine().evaluate(check, target, inventory)

    assert applies is True
    assert reason is None


def test_required_feature_not_detected_skips_check_with_spanish_reason():
    target = Target("t1", "T1", "dev", "standalone", "p1", operating_system={"platform": "linux"})
    inventory = Inventory(
        "t1",
        "standalone",
        "dev",
        features={"oracle_rac": {"detected": False, "status": "not_detected", "reason": "cluster_database = FALSE"}},
    )
    check = Check("c1", "g1", "C1", applicability={"requires_feature": "oracle_rac"})

    applies, reason = ApplicabilityEngine().evaluate(check, target, inventory)

    assert applies is False
    assert "no está detectada" in reason
    assert "cluster_database = FALSE" in reason


def test_missing_required_feature_skips_check():
    target = Target("t1", "T1", "dev", "standalone", "p1", operating_system={"platform": "linux"})
    inventory = Inventory("t1", "standalone", "dev", features={})
    check = Check("c1", "g1", "C1", applicability={"requires_feature": "oracle_rac"})

    applies, reason = ApplicabilityEngine().evaluate(check, target, inventory)

    assert applies is False
    assert "no existe en el inventario" in reason


def test_unknown_required_feature_skips_check():
    target = Target("t1", "T1", "dev", "standalone", "p1", operating_system={"platform": "linux"})
    inventory = Inventory(
        "t1",
        "standalone",
        "dev",
        features={"oracle_rac": {"detected": False, "status": "unknown", "reason": "No se pudo consultar V$PARAMETER."}},
    )
    check = Check("c1", "g1", "C1", applicability={"requires_feature": "oracle_rac"})

    applies, reason = ApplicabilityEngine().evaluate(check, target, inventory)

    assert applies is False
    assert "no pudo determinarse" in reason


def test_skipped_result_does_not_reduce_score():
    summary = summarize([
        Result("c1", "g1", ResultStatus.SKIPPED, "C1", skipped_reason="La validación no aplica para este target."),
    ])

    assert summary["score"] == 100
