"""一次性验收服务（verify）。

执行后退出，并以退出码报告本次验收结果：全部通过为 0，任一失败为 1。
步骤：构建检查（字节码编译）→ 代码测试（单元测试）→ 页面与健康路径的
HTTP 冒烟 → 围绕决策表边界的 API 验收（64 变量 / 96 规则上限、
safe 与 !safe 无空洞无重叠、仅 armed 的首个空洞、不同动作重叠的首个
赋值与按标识排序的命中规则、单遍错误定位、2^64 空间精确裁决），以及
危险偏序单调性：通过时的逐等级覆盖摘要、降级反例的稳定首个证据（先低
危险后高危险，含两侧规则/动作/等级）、假值更危险方向、危险方向/等级
缺失/未知/重复的明确拒绝、未冻结（空洞/重叠）时拒绝单调性裁决。
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
        good = status == 200 and "姿态保护控制器" in body and "/api/audit" in body
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
    # safe=true→hold(低)、safe=false→alarm(高)，故假值更危险时整体单调。
    status, data = http_audit({
        "variables": ["safe"],
        "rules": [rule("R1", "hold", "safe"), rule("R2", "alarm", "!safe")],
        "danger": {"safe": "false"},
        "levels": {"hold": 1, "alarm": 2},
    })
    ok = (
        status == 200 and data.get("ok") and data.get("verdict") == "PASS"
        and data.get("frozen") is True
        and data["holes"]["count"] == 0 and data["holes"]["first"] is None
        and data["overlaps"]["count"] == 0 and data["overlaps"]["first"] is None
        and len(data["rules"]) == 2 and all(r["nodes"] == 3 for r in data["rules"])
        and data["monotonicity"]["verdict"] == "PASS"
        and data["monotonicity"]["violating_pairs"] == 0
        and data["monotonicity"]["counterexample"] is None
        and sum(c["assignments"] for c in data["monotonicity"]["coverage"]) == 2
    )
    return check("验收：safe 与 !safe 无空洞无重叠且危险偏序单调", ok,
                 f"verdict={data.get('verdict')} holes={data.get('holes', {}).get('count')} "
                 f"overlaps={data.get('overlaps', {}).get('count')}")


def case_armed_first_hole() -> bool:
    status, data = http_audit({
        "variables": ["armed"],
        "rules": [rule("R1", "hold", "armed")],
        "danger": {"armed": "true"},
        "levels": {"hold": 1},
    })
    first = data.get("holes", {}).get("first")
    ok = (
        status == 200 and data.get("ok") and data.get("verdict") == "FAIL"
        and data.get("frozen") is False and data.get("monotonicity") is None
        and data["holes"]["count"] == 1 and first == {"armed": False}
        and data["overlaps"]["count"] == 0
    )
    return check("验收：仅 armed 时首个空洞为 armed=false 且未冻结不裁决单调性", ok, f"first={first}")


def case_overlap_first_assignment() -> bool:
    status, data = http_audit({
        "variables": ["armed", "safe"],
        "rules": [
            rule("R2", "alarm", "safe"),
            rule("R1", "hold", "safe | armed"),
            rule("R3", "hold", "!safe & !armed"),
        ],
        "danger": {"armed": "true", "safe": "true"},
        "levels": {"hold": 1, "alarm": 2},
    })
    ov = data.get("overlaps", {})
    ok = (
        status == 200 and data.get("ok") and data.get("verdict") == "FAIL"
        and data.get("frozen") is False and data.get("monotonicity") is None
        and ov.get("count") == 2
        and ov.get("first") == {"armed": False, "safe": True}
        and ov.get("rules") == ["R1", "R2"]
        and ov.get("actions") == ["alarm", "hold"]
    )
    return check("验收：不同动作重叠给出首个赋值与按标识排序的命中规则并拒绝单调性裁决", ok,
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
                "syntax", "unknown_variable", "duplicate_rule_id", "empty_action",
                "missing_danger_direction", "missing_action_level"}
    ok = status == 422 and not data.get("ok") and expected <= kinds
    return check("验收：非法标识/未知变量/空条件/残缺语法/方向与等级缺失等一次定位", ok,
                 f"kinds={sorted(kinds)}")


def case_variable_limit() -> bool:
    vars64 = [f"v{i:02d}" for i in range(64)]
    _, ok64 = http_audit({"variables": vars64, "rules": [],
                          "danger": {v: "true" for v in vars64}, "levels": {}})
    _, over = http_audit({"variables": [f"v{i:02d}" for i in range(65)], "rules": []})
    good = (
        ok64.get("ok") is True
        and over.get("ok") is False
        and "too_many_variables" in {e.get("kind") for e in over.get("errors", [])}
    )
    return check("验收：变量上限 64 通过 / 65 拒绝", good)


def case_rule_limit() -> bool:
    rules = [rule(f"R{i:02d}", "hold", "a") for i in range(96)]
    payload = {"variables": ["a"], "rules": rules, "danger": {"a": "true"}, "levels": {"hold": 1}}
    _, ok96 = http_audit(payload)
    _, over = http_audit({**payload, "rules": rules + [rule("R96", "hold", "a")]})
    good = (
        ok96.get("ok") is True
        and over.get("ok") is False
        and "too_many_rules" in {e.get("kind") for e in over.get("errors", [])}
    )
    return check("验收：规则上限 96 通过 / 97 拒绝", good)


def case_exact_full_space() -> bool:
    variables = [f"v{i:02d}" for i in range(64)]
    rules = []
    for k in range(64):
        prefix = " & ".join(f"!v{i:02d}" for i in range(k))
        cond = f"{prefix} & v{k:02d}" if prefix else "v00"
        rules.append(rule(f"R{k:02d}", f"act{k:02d}", cond))
    rules.append(rule("R64", "act64", " & ".join(f"!v{i:02d}" for i in range(64))))
    # 链序：先出现 v00=true 者最危险、等级最高；全假最低。
    levels = {f"act{k:02d}": 64 - k for k in range(64)}
    levels["act64"] = 0
    status, data = http_audit({
        "variables": variables, "rules": rules,
        "danger": {v: "true" for v in variables}, "levels": levels,
    })
    mono = data.get("monotonicity") or {}
    ok = (
        status == 200 and data.get("ok") and data.get("verdict") == "PASS"
        and data.get("space") == 1 << 64
        and data["holes"]["count"] == 0 and data["overlaps"]["count"] == 0
        and mono.get("verdict") == "PASS"
        and mono.get("comparable_pairs") == 3 ** 64
        and sum(c.get("assignments", 0) for c in mono.get("coverage", [])) == 1 << 64
    )
    return check("验收：2^64 赋值空间精确裁决且 3^64 可比对全部检验（非枚举/抽样/相邻翻转）", ok,
                 f"verdict={data.get('verdict')} space={data.get('space')}")


# ----------------------------------------------------- 单调性专项验收
THREE_TIER_RULES = [
    rule("R1", "hold", "!armed"),
    rule("R2", "arm", "armed & !tilt"),
    rule("R3", "emer", "armed & tilt"),
]
THREE_TIER_VARS = ["armed", "tilt"]
TRUE_DANGER = {"armed": "true", "tilt": "true"}


def case_monotonicity_pass_summary() -> bool:
    status, data = http_audit({
        "variables": THREE_TIER_VARS, "rules": THREE_TIER_RULES,
        "danger": TRUE_DANGER, "levels": {"hold": 1, "arm": 2, "emer": 3},
    })
    mono = data.get("monotonicity") or {}
    coverage = {c["action"]: c for c in mono.get("coverage", [])}
    ok = (
        status == 200 and data.get("verdict") == "PASS"
        and mono.get("verdict") == "PASS"
        and mono.get("comparable_pairs") == 9 and mono.get("violating_pairs") == 0
        and mono.get("counterexample") is None
        and coverage["hold"]["level"] == 1 and coverage["hold"]["assignments"] == 2
        and coverage["arm"]["assignments"] == 1 and coverage["emer"]["assignments"] == 1
        and coverage["hold"]["rules"] == ["R1"]
    )
    return check("验收：单调性通过并展示每个动作等级的规范覆盖摘要", ok,
                 f"coverage={[(c['action'], c['level'], c['assignments_text']) for c in mono.get('coverage', [])]}")


def case_monotonicity_first_counterexample() -> bool:
    # 等级反配：越危险等级越低；首个反例按 α-major 稳定返回。
    status, data = http_audit({
        "variables": THREE_TIER_VARS, "rules": THREE_TIER_RULES,
        "danger": TRUE_DANGER, "levels": {"hold": 3, "arm": 2, "emer": 1},
    })
    mono = data.get("monotonicity") or {}
    ce = mono.get("counterexample") or {}
    lo, hi = ce.get("less_dangerous") or {}, ce.get("more_dangerous") or {}
    ok = (
        status == 200 and data.get("verdict") == "FAIL"
        and mono.get("verdict") == "FAIL" and mono.get("violating_pairs", 0) >= 3
        and lo.get("assignment") == {"armed": False, "tilt": False}
        and lo.get("rules") == ["R1"] and lo.get("actions") == ["hold"] and lo.get("level") == 3
        and hi.get("assignment") == {"armed": True, "tilt": False}
        and hi.get("rules") == ["R2"] and hi.get("actions") == ["arm"] and hi.get("level") == 2
    )
    return check("验收：降级时稳定返回首个反例并列出两侧规则/动作/等级", ok,
                 f"lo={lo.get('assignment')}/{lo.get('actions')}/L{lo.get('level')} "
                 f"hi={hi.get('assignment')}/{hi.get('actions')}/L{hi.get('level')} "
                 f"pairs={mono.get('violating_pairs_text')}")


def case_false_more_dangerous_direction() -> bool:
    base = {"variables": ["safe"],
            "rules": [rule("R1", "hold", "safe"), rule("R2", "alarm", "!safe")],
            "levels": {"hold": 1, "alarm": 2}}
    _, as_true = http_audit({**base, "danger": {"safe": "true"}})
    _, as_false = http_audit({**base, "danger": {"safe": "false"}})
    ce = (as_true.get("monotonicity") or {}).get("counterexample") or {}
    ok = (
        as_true.get("verdict") == "FAIL"
        and (ce.get("less_dangerous") or {}).get("assignment") == {"safe": False}
        and (ce.get("more_dangerous") or {}).get("assignment") == {"safe": True}
        and as_false.get("verdict") == "PASS"
        and as_false["monotonicity"]["violating_pairs"] == 0
    )
    return check("验收：同一规则在真/假危险方向下分别得到反例与通过", ok,
                 f"true-direction={as_true.get('verdict')} false-direction={as_false.get('verdict')}")


def case_config_rejected() -> bool:
    status, data = http_audit({
        "variables": ["armed", "tilt"],
        "rules": THREE_TIER_RULES,
        # armed 缺方向；tilt 取值非法
        "danger": {"tilt": "up", "ghost": "true"},
        # emer 缺等级；ghost 未知动作；hold/arm 等级重复；x 非整数
        "levels": {"hold": 1, "arm": 1, "ghost": 9, "x": "?"},
    })
    kinds = {e.get("kind") for e in data.get("errors", [])}
    expected = {"missing_danger_direction", "invalid_danger_direction",
                "unknown_danger_variable", "missing_action_level",
                "unknown_action", "duplicate_level", "invalid_level"}
    ok = status == 422 and not data.get("ok") and expected <= kinds
    return check("验收：方向遗漏/非法、动作未知、等级重复/缺失/非整数被明确拒绝", ok,
                 f"kinds={sorted(kinds)}")


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
            case_monotonicity_pass_summary,
            case_monotonicity_first_counterexample,
            case_false_more_dangerous_direction,
            case_config_rejected,
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
