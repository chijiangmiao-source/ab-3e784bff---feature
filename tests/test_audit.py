import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import audit


def rule(rid, action, condition):
    return {"id": rid, "action": action, "condition": condition}


class DecisionTest(unittest.TestCase):
    def test_safe_and_not_safe_passes(self):
        result = audit.audit(
            ["safe"],
            [rule("R1", "hold", "safe"), rule("R2", "alarm", "!safe")],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["holes"]["count"], 0)
        self.assertEqual(result["holes"]["count_text"], "0")
        self.assertIsNone(result["holes"]["first"])
        self.assertEqual(result["overlaps"]["count"], 0)
        self.assertEqual(result["overlaps"]["first"], None)
        self.assertEqual(len(result["rules"]), 2)
        for summary in result["rules"]:
            self.assertEqual(summary["nodes"], 3)  # 根节点 + 两个终端
        self.assertIn("无空洞", result["conclusion"])

    def test_armed_only_reports_first_hole(self):
        result = audit.audit(["armed"], [rule("R1", "hold", "armed")])
        self.assertTrue(result["ok"])
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["holes"]["count"], 1)
        self.assertEqual(result["holes"]["first"], {"armed": False})
        self.assertEqual(result["overlaps"]["count"], 0)

    def test_overlap_reports_first_assignment_and_sorted_rules(self):
        result = audit.audit(
            ["armed", "safe"],
            [
                rule("R2", "alarm", "safe"),
                rule("R1", "hold", "safe | armed"),
                rule("R3", "hold", "!safe & !armed"),
            ],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["holes"]["count"], 0)
        self.assertEqual(result["overlaps"]["count"], 2)
        self.assertEqual(result["overlaps"]["first"], {"armed": False, "safe": True})
        self.assertEqual(result["overlaps"]["rules"], ["R1", "R2"])
        self.assertEqual(result["overlaps"]["actions"], ["alarm", "hold"])

    def test_same_action_overlap_is_not_conflict(self):
        result = audit.audit(
            ["a"],
            [rule("R1", "hold", "a"), rule("R2", "hold", "a | !a")],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["overlaps"]["count"], 0)
        self.assertEqual(result["verdict"], "PASS")

    def test_variable_order_is_ascii(self):
        result = audit.audit(["b", "A", "a"], [rule("R1", "hold", "b")])
        self.assertEqual(result["variable_order"], ["A", "a", "b"])
        # 首个空洞按 ASCII 变量序、假先于真
        self.assertEqual(result["holes"]["first"], {"A": False, "a": False, "b": False})

    def test_exact_counts_without_enumeration(self):
        # 64 个变量、65 条两两互斥且全覆盖的规则：2^64 空间精确裁决
        variables = [f"v{i:02d}" for i in range(64)]
        rules = []
        for k in range(64):
            prefix = " & ".join(f"!v{i:02d}" for i in range(k))
            cond = f"{prefix} & v{k:02d}" if prefix else "v00"
            rules.append(rule(f"R{k:02d}", "actA" if k % 2 == 0 else "actB", cond))
        rules.append(rule("R64", "actA", " & ".join(f"!v{i:02d}" for i in range(64))))
        result = audit.audit(variables, rules)
        self.assertTrue(result["ok"])
        self.assertEqual(result["space"], 1 << 64)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["holes"]["count"], 0)
        self.assertEqual(result["overlaps"]["count"], 0)

    def test_no_rules_everything_is_hole(self):
        result = audit.audit(["a", "b"], [])
        self.assertTrue(result["ok"])
        self.assertEqual(result["holes"]["count"], 4)
        self.assertEqual(result["holes"]["first"], {"a": False, "b": False})


class ValidationTest(unittest.TestCase):
    def test_all_errors_located_in_one_pass(self):
        result = audit.audit(
            ["1bad", "ok", "ok"],
            [
                rule("r1", "a", ""),                 # 空条件
                rule("r2", "b", "ok &"),             # 残缺语法
                rule("r3", "c", "ghost | ok"),       # 未知变量
                rule("r1", "d", "ok"),               # 规则标识重复
                rule("9x", "", "ok"),                # 非法规则标识 + 空动作
            ],
        )
        self.assertFalse(result["ok"])
        kinds = [e["kind"] for e in result["errors"]]
        for expected in (
            "illegal_identifier",   # 变量 1bad
            "duplicate_variable",   # 变量 ok 重复
            "empty_condition",
            "syntax",
            "unknown_variable",
            "duplicate_rule_id",
            "empty_action",
        ):
            self.assertIn(expected, kinds)
        self.assertGreaterEqual(kinds.count("illegal_identifier"), 2)  # 变量与规则标识各一
        # 每条错误都带有可读信息
        for err in result["errors"]:
            self.assertTrue(err["message"])

    def test_variable_limit_boundary(self):
        ok_result = audit.audit([f"v{i:02d}" for i in range(64)], [])
        self.assertTrue(ok_result["ok"])
        over = audit.audit([f"v{i:02d}" for i in range(65)], [])
        self.assertFalse(over["ok"])
        self.assertIn("too_many_variables", [e["kind"] for e in over["errors"]])

    def test_rule_limit_boundary(self):
        rules = [rule(f"R{i:02d}", "hold", "a") for i in range(96)]
        self.assertTrue(audit.audit(["a"], rules)["ok"])
        over = audit.audit(["a"], rules + [rule("R96", "hold", "a")])
        self.assertFalse(over["ok"])
        self.assertIn("too_many_rules", [e["kind"] for e in over["errors"]])

    def test_invalid_payload_types(self):
        self.assertFalse(audit.audit("oops", [])["ok"])
        self.assertFalse(audit.audit([], "oops")["ok"])
        self.assertFalse(audit.audit([], ["oops"])["ok"])


if __name__ == "__main__":
    unittest.main()
