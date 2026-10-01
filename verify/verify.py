"""一次性验收服务（verify）。

执行后退出，并以退出码报告本次验收结果：全部通过为 0，任一失败为 1。
步骤：构建检查（字节码编译）→ 代码测试（单元测试）→ 页面与健康路径的
HTTP 冒烟 → 围绕决策表边界的 API 验收（64 变量 / 96 规则上限、
safe 与 !safe 无空洞无重叠、仅 armed 的首个空洞、不同动作重叠的首个
赋值与按标识排序的命中规则、单遍错误定位、2^64 空间精确裁决）→
危险偏序单调复核验收（通过摘要、降级反例双侧命中、配置错误拒绝、
3^64 偏序对非枚举精确检验）。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB_URL = os.environ.get("WEB_URL", "http://127.0.0.1:8000").rstrip("/")
WAIT_SECONDS = float(os.environ.get("VERIFY_WAIT", "60"))

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {name}"
    if detail:
        line += f" — {detail}"
    print(line, flush=True)


def http_get(path: str):
    with urllib.request.urlopen(WEB_URL + path, timeout=5) as resp:
        return resp.status, resp.read().decode("utf-8")


def http_audit(payload: dict):
    req = urllib.request.Request(
        WEB_URL + "/api/audit",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def rule(rid, action, condition):
    return {"id": rid, "action": action, "condition": condition}


# ---------------------------------------------------------------- 步骤
def step_build_check() -> bool:
    proc = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", "app", "tests", "verify"],
        cwd=ROOT, capture_output=True, text=True,
    )
    ok = proc.returncode == 0
    record("构建检查：compileall app/tests/verify", ok, (proc.stderr or proc.stdout).strip()[:400])
    return ok


def step_unit_tests() -> bool:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
        cwd=ROOT, capture_output=True, text=True,
    )
    ok = proc.returncode == 0
    tail = (proc.stderr or proc.stdout).strip().splitlines()
    record("代码测试：unittest 单元套件", ok, tail[-1] if tail else "")
    if not ok:
        print(proc.stderr[-2000:], flush=True)
    return ok


def wait_for_web() -> bool:
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            status, body = http_get("/health")
            if status == 200 and json.loads(body).get("status") == "ok":
                record("等待 web 就绪：/health", True, WEB_URL)
                return True
        except Exception:
            pass
        time.sleep(1)
    record("等待 web 就绪：/health", False, f"{WAIT_SECONDS}s 内未就绪（{WEB_URL}）")
    return False


def step_http_smoke() -> bool:
    ok = True
    try:
        status, body = http_get("/health")
        good = status == 200 and json.loads(body).get("status") == "ok"
        record("HTTP 冒烟：GET /health", good, f"status={status} body={body.strip()}")
        ok = ok and good
    except Exception as exc:
        record("HTTP 冒烟：GET /health", False, repr(exc))
        ok = False
    try:
        status, body = http_get("/")
        good = (
            status == 200
            and "姿态保护控制器" in body
            and "/api/audit" in body
            and "/api/monotonicity" in body
            and "危险偏序" in body
        )
        record("HTTP 冒烟：GET / 审计页面", good, f"status={status} bytes={len(body)}")
        ok = ok and good
    except Exception as exc:
        record("HTTP 冒烟：GET / 审计页面", False, repr(exc))
        ok = False
    return ok


# ---------------------------------------------------------------- 验收用例
def check(name, condition, detail=""):
    record(name, bool(condition), detail)
    return bool(condition)


def case_safe_not_safe() -> bool:
    status, data = http_audit({
        "variables": ["safe"],
        "rules": [rule("R1", "hold", "safe"), rule("R2", "alarm", "!safe")],
    })
    ok = (
        status == 200 and data.get("ok") and data.get("verdict") == "PASS"
        and data["holes"]["count"] == 0 and data["holes"]["first"] is None
        and data["overlaps"]["count"] == 0 and data["overlaps"]["first"] is None
        and len(data["rules"]) == 2 and all(r["nodes"] == 3 for r in data["rules"])
    )
    return check("验收：safe 与 !safe 无空洞且无重叠", ok,
                 f"verdict={data.get('verdict')} holes={data.get('holes', {}).get('count')} "
                 f"overlaps={data.get('overlaps', {}).get('count')}")


def case_armed_first_hole() -> bool:
    status, data = http_audit({
        "variables": ["armed"],
        "rules": [rule("R1", "hold", "armed")],
    })
    first = data.get("holes", {}).get("first")
    ok = (
        status == 200 and data.get("ok") and data.get("verdict") == "FAIL"
        and data["holes"]["count"] == 1 and first == {"armed": False}
        and data["overlaps"]["count"] == 0
    )
    return check("验收：仅 armed 时首个空洞为 armed=false", ok, f"first={first}")


def case_overlap_first_assignment() -> bool:
    status, data = http_audit({
        "variables": ["armed", "safe"],
        "rules": [
            rule("R2", "alarm", "safe"),
            rule("R1", "hold", "safe | armed"),
            rule("R3", "hold", "!safe & !armed"),
        ],
    })
    ov = data.get("overlaps", {})
    ok = (
        status == 200 and data.get("ok") and data.get("verdict") == "FAIL"
        and ov.get("count") == 2
        and ov.get("first") == {"armed": False, "safe": True}
        and ov.get("rules") == ["R1", "R2"]
        and ov.get("actions") == ["alarm", "hold"]
    )
    return check("验收：不同动作重叠给出首个赋值与按标识排序的命中规则", ok,
                 f"first={ov.get('first')} rules={ov.get('rules')}")


def case_errors_in_one_pass() -> bool:
    status, data = http_audit({
        "variables": ["1bad", "ok", "ok"],
        "rules": [
            rule("r1", "a", ""),
            rule("r2", "b", "ok &"),
            rule("r3", "c", "ghost | ok"),
            rule("r1", "d", "ok"),
            rule("9x", "", "ok"),
        ],
    })
    kinds = {e.get("kind") for e in data.get("errors", [])}
    expected = {"illegal_identifier", "duplicate_variable", "empty_condition",
                "syntax", "unknown_variable", "duplicate_rule_id", "empty_action"}
    ok = status == 422 and not data.get("ok") and expected <= kinds
    return check("验收：非法标识/未知变量/空条件/残缺语法等一次定位", ok,
                 f"kinds={sorted(kinds)}")


def case_variable_limit() -> bool:
    _, ok64 = http_audit({"variables": [f"v{i:02d}" for i in range(64)], "rules": []})
    _, over = http_audit({"variables": [f"v{i:02d}" for i in range(65)], "rules": []})
    good = (
        ok64.get("ok") is True
        and over.get("ok") is False
        and "too_many_variables" in {e.get("kind") for e in over.get("errors", [])}
    )
    return check("验收：变量上限 64 通过 / 65 拒绝", good)


def case_rule_limit() -> bool:
    rules = [rule(f"R{i:02d}", "hold", "a") for i in range(96)]
    _, ok96 = http_audit({"variables": ["a"], "rules": rules})
    _, over = http_audit({"variables": ["a"], "rules": rules + [rule("R96", "hold", "a")]})
    good = (
        ok96.get("ok") is True
        and over.get("ok") is False
        and "too_many_rules" in {e.get("kind") for e in over.get("errors", [])}
    )
    return check("验收：规则上限 96 通过 / 97 拒绝", good)


def http_monotonicity(payload: dict):
    req = urllib.request.Request(
        WEB_URL + "/api/monotonicity",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def case_exact_full_space() -> bool:
    variables = [f"v{i:02d}" for i in range(64)]
    rules = []
    for k in range(64):
        prefix = " & ".join(f"!v{i:02d}" for i in range(k))
        cond = f"{prefix} & v{k:02d}" if prefix else "v00"
        rules.append(rule(f"R{k:02d}", "actA" if k % 2 == 0 else "actB", cond))
    rules.append(rule("R64", "actA", " & ".join(f"!v{i:02d}" for i in range(64))))
    status, data = http_audit({"variables": variables, "rules": rules})
    ok = (
        status == 200 and data.get("ok") and data.get("verdict") == "PASS"
        and data.get("space") == 1 << 64
        and data["holes"]["count"] == 0 and data["overlaps"]["count"] == 0
    )
    return check("验收：2^64 赋值空间精确裁决（非枚举/抽样）", ok,
                 f"verdict={data.get('verdict')} space={data.get('space')}")


# ----------------------------------------------------- 危险偏序单调复核验收
def case_monotonicity_pass() -> bool:
    status, data = http_monotonicity({
        "variables": ["armed", "safe"],
        "rules": [rule("R1", "hold", "!armed"), rule("R2", "alarm", "armed")],
        "directions": {"armed": "high", "safe": "low"},
        "levels": {"hold": 1, "alarm": 2},
    })
    good = (
        status == 200 and data.get("ok") and data.get("monotonicity") == "PASS"
        and data.get("ordered_pairs") == 9 and data.get("violating_pairs") == 0
        and data.get("counterexample") is None
        and [c["action"] for c in data.get("coverage", [])] == ["hold", "alarm"]
        and [c["level"] for c in data.get("coverage", [])] == [1, 2]
        and sum(c["assignments"] for c in data.get("coverage", [])) == 4
    )
    return check("验收：单调复核通过并给出每动作等级规范覆盖摘要", good,
                 f"verdict={data.get('monotonicity')} pairs={data.get('ordered_pairs')} "
                 f"violating={data.get('violating_pairs')}")


def case_monotonicity_counterexample() -> bool:
    status, data = http_monotonicity({
        "variables": ["armed", "safe"],
        "rules": [rule("R1", "hold", "!armed"), rule("R2", "alarm", "armed")],
        "directions": {"armed": "high", "safe": "low"},
        "levels": {"hold": 2, "alarm": 1},
    })
    ce = data.get("counterexample") or {}
    less, more = ce.get("less_dangerous") or {}, ce.get("more_dangerous") or {}
    good = (
        status == 200 and data.get("ok") and data.get("monotonicity") == "FAIL"
        and data.get("violating_pairs") == 3
        and less.get("assignment") == {"armed": False, "safe": False}
        and less.get("action") == "hold" and less.get("level") == 2
        and less.get("rules") == ["R1"]
        and more.get("assignment") == {"armed": True, "safe": False}
        and more.get("action") == "alarm" and more.get("level") == 1
        and more.get("rules") == ["R2"]
    )
    return check("验收：等级倒置稳定返回首个反例（先 α 后 β）及双侧命中规则/动作/等级", good,
                 f"violating={data.get('violating_pairs')} "
                 f"α={less.get('assignment')}->{less.get('action')}@{less.get('level')} "
                 f"β={more.get('assignment')}->{more.get('action')}@{more.get('level')}")


def case_monotonicity_config_errors() -> bool:
    status, data = http_monotonicity({
        "variables": ["a", "b"],
        "rules": [rule("R1", "hold", "!a"), rule("R2", "alarm", "a")],
        "directions": {"a": "sideways", "ghost": "high"},  # 非法值 + 未知变量 + b 遗漏
        "levels": {"hold": 2, "alarm": 2, "ghost": 0},     # 重复 + 未知动作
    })
    kinds = {e.get("kind") for e in data.get("errors", [])}
    expected = {
        "invalid_direction", "unknown_variable", "missing_variable_direction",
        "duplicate_level", "unknown_action",
    }
    good = status == 422 and not data.get("ok") and expected <= kinds
    return check("验收：方向遗漏/非法、未知动作、等级重复一次定位并拒绝", good,
                 f"kinds={sorted(kinds)}")


def case_monotonicity_requires_frozen_coverage() -> bool:
    # 仅 armed 有空洞：不得在未冻结（有空洞/重叠）结论上做单调复核。
    status, data = http_monotonicity({
        "variables": ["armed"],
        "rules": [rule("R1", "hold", "armed")],
        "directions": {"armed": "high"},
        "levels": {"hold": 1},
    })
    kinds = {e.get("kind") for e in data.get("errors", [])}
    good = status == 422 and not data.get("ok") and "coverage_incomplete" in kinds
    return check("验收：空洞/重叠未消除时拒绝单调复核（只接受冻结结论）", good,
                 f"kinds={sorted(kinds)}")


def case_monotonicity_3_64_pairs() -> bool:
    variables = [f"v{i:02d}" for i in range(64)]
    rules = [
        {"id": "R1", "action": "hold", "condition": "!v00"},
        {"id": "R2", "action": "alarm", "condition": "v00"},
    ]
    # 全 high：v00 决定等级，其余无关，单调通过；偏序对恰为 3^64。
    status_pass, data_pass = http_monotonicity({
        "variables": variables, "rules": rules,
        "directions": {v: "high" for v in variables},
        "levels": {"hold": 1, "alarm": 2},
    })
    # 倒置后：降级对恰为 3^63（v00 由假到真，其余 63 变量各自 3 种合法组合）。
    status_fail, data_fail = http_monotonicity({
        "variables": variables, "rules": rules,
        "directions": {v: "high" for v in variables},
        "levels": {"hold": 2, "alarm": 1},
    })
    good = (
        status_pass == 200 and data_pass.get("monotonicity") == "PASS"
        and data_pass.get("ordered_pairs") == 3 ** 64
        and data_pass.get("violating_pairs") == 0
        and status_fail == 200 and data_fail.get("monotonicity") == "FAIL"
        and data_fail.get("violating_pairs") == 3 ** 63
    )
    return check("验收：3^64 偏序赋值对在共享 ROBDD 上精确检验（非枚举/抽样/相邻翻转）", good,
                 f"pass_pairs={data_pass.get('ordered_pairs_text')} "
                 f"fail_violating={data_fail.get('violating_pairs_text')}")


def main() -> int:
    print(f"verify 开始：目标 {WEB_URL}", flush=True)
    all_ok = True
    all_ok &= step_build_check()
    all_ok &= step_unit_tests()
    if wait_for_web():
        all_ok &= step_http_smoke()
        for case in (
            case_safe_not_safe,
            case_armed_first_hole,
            case_overlap_first_assignment,
            case_errors_in_one_pass,
            case_variable_limit,
            case_rule_limit,
            case_exact_full_space,
            case_monotonicity_pass,
            case_monotonicity_counterexample,
            case_monotonicity_config_errors,
            case_monotonicity_requires_frozen_coverage,
            case_monotonicity_3_64_pairs,
        ):
            try:
                all_ok &= case()
            except Exception as exc:  # 单个用例异常不中断其余核对
                record(f"验收：{case.__name__}", False, f"异常 {exc!r}")
                all_ok = False
    else:
        all_ok = False

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"verify 结束：{passed}/{len(RESULTS)} 项通过", flush=True)
    code = 0 if all_ok else 1
    print(f"verify 退出码：{code}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
