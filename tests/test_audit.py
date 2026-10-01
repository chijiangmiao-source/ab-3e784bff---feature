import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import audit


def rule(rid, action, condition):
    return {"id": rid, "action": action, "condition": condition}


class DecisionTest(unittest.TestCase):
    def test_safe_and_not_safe_passes(self):
        # safe=true→hold(低)；safe=false→alarm(高)，故假值更危险时单调。
        result = audit.audit(
            ["safe"],
            [rule("R1", "hold", "safe"), rule("R2", "alarm", "!safe")],
            {"safe": "false"},
            {"hold": 1, "alarm": 2},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["frozen"])
        self.assertEqual(result["holes"]["count"], 0)
        self.assertEqual(result["holes"]["count_text"], "0")
        self.assertIsNone(result["holes"]["first"])
        self.assertEqual(result["overlaps"]["count"], 0)
        self.assertEqual(result["overlaps"]["first"], None)
        self.assertEqual(len(result["rules"]), 2)
        for summary in result["rules"]:
            self.assertEqual(summary["nodes"], 3)  # 根节点 + 两个终端
        self.assertIn("无空洞", result["conclusion"])
        # 单调性通过：3 对可比赋值（自身对与 (false,true) 方向），无反例
        mono = result["monotonicity"]
        self.assertEqual(mono["verdict"], "PASS")
        self.assertIsNone(mono["counterexample"])
        self.assertEqual(mono["violating_pairs"], 0)
        self.assertEqual(
            sorted((c["action"], c["level"], c["assignments"]) for c in mono["coverage"]),
            [("alarm", 2, 1), ("hold", 1, 1)],
        )

    def test_armed_only_reports_first_hole(self):
        result = audit.audit(
            ["armed"], [rule("R1", "hold", "armed")], {"armed": "true"}, {"hold": 1}
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["verdict"], "FAIL")
        self.assertFalse(result["frozen"])
        self.assertIsNone(result["monotonicity"])  # 未冻结不做单调性裁决
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
            {"armed": "true", "safe": "true"},
            {"hold": 1, "alarm": 2},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["verdict"], "FAIL")
        self.assertFalse(result["frozen"])
        self.assertIsNone(result["monotonicity"])
        self.assertEqual(result["holes"]["count"], 0)
        self.assertEqual(result["overlaps"]["count"], 2)
        self.assertEqual(result["overlaps"]["first"], {"armed": False, "safe": True})
        self.assertEqual(result["overlaps"]["rules"], ["R1", "R2"])
        self.assertEqual(result["overlaps"]["actions"], ["alarm", "hold"])

    def test_same_action_overlap_is_not_conflict(self):
        result = audit.audit(
            ["a"],
            [rule("R1", "hold", "a"), rule("R2", "hold", "a | !a")],
            {"a": "true"},
            {"hold": 1},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["overlaps"]["count"], 0)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["monotonicity"]["verdict"], "PASS")

    def test_variable_order_is_ascii(self):
        result = audit.audit(
            ["b", "A", "a"],
            [rule("R1", "hold", "b")],
            {"A": "true", "a": "true", "b": "true"},
            {"hold": 1},
        )
        self.assertEqual(result["variable_order"], ["A", "a", "b"])
        # 首个空洞按 ASCII 变量序、假先于真
        self.assertEqual(result["holes"]["first"], {"A": False, "a": False, "b": False})

    def test_exact_counts_without_enumeration(self):
        # 64 个变量、65 条两两互斥且全覆盖的规则：2^64 空间精确裁决覆盖；
        # 两动作在链序上交替，单调性预期 FAIL，但仍须精确执行而非近似。
        variables = [f"v{i:02d}" for i in range(64)]
        rules = []
        for k in range(64):
            prefix = " & ".join(f"!v{i:02d}" for i in range(k))
            cond = f"{prefix} & v{k:02d}" if prefix else "v00"
            rules.append(rule(f"R{k:02d}", f"act{k:02d}", cond))
        rules.append(rule("R64", "act64", " & ".join(f"!v{i:02d}" for i in range(64))))
        levels = {f"act{k:02d}": 64 - k for k in range(64)}
        levels["act64"] = 0
        result = audit.audit(variables, rules, {v: "true" for v in variables}, levels)
        self.assertTrue(result["ok"])
        self.assertEqual(result["space"], 1 << 64)
        self.assertTrue(result["frozen"])
        self.assertEqual(result["coverage_verdict"], "PASS")
        self.assertEqual(result["holes"]["count"], 0)
        self.assertEqual(result["overlaps"]["count"], 0)
        # 单调链序：v00 先真者最危险、等级最高；全部比较通过
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["monotonicity"]["verdict"], "PASS")
        self.assertEqual(result["monotonicity"]["comparable_pairs"], 3 ** 64)
        self.assertEqual(sum(c["assignments"] for c in result["monotonicity"]["coverage"]), 1 << 64)

    def test_no_rules_everything_is_hole(self):
        result = audit.audit(["a", "b"], [], {"a": "true", "b": "true"}, {})
        self.assertTrue(result["ok"])
        self.assertFalse(result["frozen"])
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
        vars64 = [f"v{i:02d}" for i in range(64)]
        ok_result = audit.audit(vars64, [], {v: "true" for v in vars64}, {})
        self.assertTrue(ok_result["ok"])
        over = audit.audit([f"v{i:02d}" for i in range(65)], [], None, None)
        self.assertFalse(over["ok"])
        self.assertIn("too_many_variables", [e["kind"] for e in over["errors"]])

    def test_rule_limit_boundary(self):
        rules = [rule(f"R{i:02d}", "hold", "a") for i in range(96)]
        self.assertTrue(
            audit.audit(["a"], rules, {"a": "true"}, {"hold": 1})["ok"]
        )
        over = audit.audit(["a"], rules + [rule("R96", "hold", "a")], {"a": "true"}, {"hold": 1})
        self.assertFalse(over["ok"])
        self.assertIn("too_many_rules", [e["kind"] for e in over["errors"]])

    def test_invalid_payload_types(self):
        self.assertFalse(audit.audit("oops", [])["ok"])
        self.assertFalse(audit.audit([], "oops")["ok"])
        self.assertFalse(audit.audit([], ["oops"])["ok"])


class MonotonicityTest(unittest.TestCase):
    def _three_tier(self, danger=None, levels=None):
        # hold: !armed；arm: armed & !tilt；emer: armed & tilt。
        return audit.audit(
            ["armed", "tilt"],
            [
                rule("R1", "hold", "!armed"),
                rule("R2", "arm", "armed & !tilt"),
                rule("R3", "emer", "armed & tilt"),
            ],
            danger or {"armed": "true", "tilt": "true"},
            levels or {"hold": 1, "arm": 2, "emer": 3},
        )

    def test_monotone_three_tier_passes(self):
        result = self._three_tier()
        self.assertEqual(result["verdict"], "PASS")
        mono = result["monotonicity"]
        self.assertEqual(mono["verdict"], "PASS")
        # 逐坐标 α≤β 的可比对数 = 3^2 = 9（两变量均真值更危险）
        self.assertEqual(mono["comparable_pairs"], 9)
        self.assertEqual(mono["pair_space"], 16)
        self.assertIsNone(mono["counterexample"])
        self.assertEqual(
            sorted((c["action"], c["assignments"]) for c in mono["coverage"]),
            [("arm", 1), ("emer", 1), ("hold", 2)],
        )

    def test_first_counterexample_is_alpha_major_then_beta(self):
        # 等级反配：hold=3、arm=2、emer=1。
        result = self._three_tier(levels={"hold": 3, "arm": 2, "emer": 1})
        self.assertEqual(result["verdict"], "FAIL")
        mono = result["monotonicity"]
        self.assertEqual(mono["verdict"], "FAIL")
        self.assertGreater(mono["violating_pairs"], 0)
        ce = mono["counterexample"]
        # 最小 α（假先于真）：全假命中 hold(3)；最小可比的降级 β 取 armed=true。
        self.assertEqual(ce["less_dangerous"]["assignment"], {"armed": False, "tilt": False})
        self.assertEqual(ce["less_dangerous"]["rules"], ["R1"])
        self.assertEqual(ce["less_dangerous"]["actions"], ["hold"])
        self.assertEqual(ce["less_dangerous"]["level"], 3)
        self.assertEqual(ce["more_dangerous"]["assignment"], {"armed": True, "tilt": False})
        self.assertEqual(ce["more_dangerous"]["rules"], ["R2"])
        self.assertEqual(ce["more_dangerous"]["actions"], ["arm"])
        self.assertEqual(ce["more_dangerous"]["level"], 2)

    def test_non_adjacent_violation_is_found(self):
        # 反例需要两坐标同时移动（非相邻翻转）：armed=false→true 且
        # tilt=false→true。设 arm 等级最高、emer 最低，则
        # α=(true,false)→arm(9)，β=(true,true)→emer(1) 是相邻翻转（tilt），
        # 也存在多坐标路径；改为 hold=9, emer=1, arm=5 时，
        # α=全假(hold,9) 到 β=(true,true)(emer,1) 跨两坐标，必须被发现。
        result = self._three_tier(levels={"hold": 9, "arm": 5, "emer": 1})
        mono = result["monotonicity"]
        self.assertEqual(mono["verdict"], "FAIL")
        ce = mono["counterexample"]
        # α-major 首个：全假；β 在 armed=true 行内假先于真，首个降级 β：
        # armed=true,tilt=false 是 arm(5) < 9 已构成降级，故首个为单坐标。
        self.assertEqual(ce["less_dangerous"]["assignment"], {"armed": False, "tilt": False})
        self.assertEqual(ce["more_dangerous"]["assignment"], {"armed": True, "tilt": False})
        # 两坐标反例同样计入精确总数（总数大于相邻翻转数）。
        self.assertGreaterEqual(mono["violating_pairs"], 3)

    def test_false_more_dangerous_direction(self):
        # safe=true→hold(低)、safe=false→alarm(高)：真值更危险时反例存在，
        # 假值更危险时通过。
        payload_vars, payload_rules = ["safe"], [rule("R1", "hold", "safe"), rule("R2", "alarm", "!safe")]
        bad = audit.audit(payload_vars, payload_rules, {"safe": "true"}, {"hold": 1, "alarm": 2})
        self.assertEqual(bad["monotonicity"]["verdict"], "FAIL")
        ce = bad["monotonicity"]["counterexample"]
        self.assertEqual(ce["less_dangerous"]["assignment"], {"safe": False})
        self.assertEqual(ce["more_dangerous"]["assignment"], {"safe": True})
        good = audit.audit(payload_vars, payload_rules, {"safe": "false"}, {"hold": 1, "alarm": 2})
        self.assertEqual(good["monotonicity"]["verdict"], "PASS")

    def test_same_level_direction_constant_level_passes(self):
        # 所有赋值同一等级：危险上升不可能降级。
        result = audit.audit(
            ["a", "b"],
            [rule("R1", "only", "a | b"), rule("R2", "only", "!a & !b")],
            {"a": "true", "b": "false"},
            {"only": 7},
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["monotonicity"]["verdict"], "PASS")
        self.assertEqual(result["monotonicity"]["coverage"][0]["assignments"], 4)


class MonotonicityValidationTest(unittest.TestCase):
    def test_missing_danger_direction_rejected(self):
        errors = audit.validate(["a", "b"], [rule("R1", "x", "a")], {"a": "true"}, {"x": 1})
        kinds = [e["kind"] for e in errors]
        self.assertIn("missing_danger_direction", kinds)
        self.assertEqual([e for e in errors if e["kind"] == "missing_danger_direction"][0]["identifier"], "b")

    def test_unknown_and_invalid_danger_rejected(self):
        errors = audit.validate(
            ["a", "b"], [rule("R1", "x", "a")], {"a": "yes", "ghost": "true"}, {"x": 1}
        )
        kinds = {e["kind"] for e in errors}
        self.assertIn("invalid_danger_direction", kinds)
        self.assertIn("unknown_danger_variable", kinds)
        self.assertIn("missing_danger_direction", kinds)  # b 完全未声明
        # a 取值非法只报一次，不重复报遗漏
        self.assertEqual(
            sum(1 for e in errors if e["kind"] == "invalid_danger_direction" and e.get("identifier") == "a"),
            1,
        )

    def test_unknown_action_level_rejected(self):
        errors = audit.validate(
            ["a"],
            [rule("R1", "x", "a"), rule("R2", "y", "!a")],
            {"a": "true"},
            {"x": 1, "ghost": 2},
        )
        self.assertIn("unknown_action", [e["kind"] for e in errors])
        self.assertIn("missing_action_level", [e["kind"] for e in errors])

    def test_duplicate_level_rejected(self):
        errors = audit.validate(
            ["a"],
            [rule("R1", "x", "a"), rule("R2", "y", "!a")],
            {"a": "true"},
            {"x": 3, "y": 3},
        )
        dup = [e for e in errors if e["kind"] == "duplicate_level"]
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup[0]["level"], 3)

    def test_invalid_level_value_rejected(self):
        errors = audit.validate(
            ["a"], [rule("R1", "x", "a")], {"a": "true"}, {"x": "2"}
        )
        self.assertIn("invalid_level", [e["kind"] for e in errors])

    def test_danger_and_levels_collected_alongside_other_errors(self):
        errors = audit.validate(["1bad", "ok"], [rule("R1", "x", "ghost")])
        kinds = {e["kind"] for e in errors}
        # 既有录入错误仍在，同时危险方向与等级缺失一并列出
        self.assertIn("illegal_identifier", kinds)
        self.assertIn("unknown_variable", kinds)
        self.assertIn("missing_danger_direction", kinds)
        self.assertIn("missing_action_level", kinds)


if __name__ == "__main__":
    unittest.main()
