from orahealthcheck.engine.applicability import ApplicabilityEngine
from orahealthcheck.models import Check, Inventory, Target


def test_non_matching_platform_is_skipped():
    target = Target("t1", "T1", "dev", "standalone", "p1", operating_system={"platform": "linux"})
    inventory = Inventory("t1", "standalone", "dev", operating_system={"platform": "linux"})
    check = Check("c1", "g1", "C1", applies_to={"platforms": ["aix"]})
    applies, reason = ApplicabilityEngine().evaluate(check, target, inventory)
    assert applies is False
    assert "plataforma" in reason
