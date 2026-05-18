"""
security_metrics.py

Jenkins stage 10에서 실행되는 보안 결과 집계 + Prometheus Pushgateway 전송 스크립트.
추가된 메트릭:
  - attack_surface_count{type}       : Semgrep 공격 표면 유형별
  - vuln_change_count{severity}      : 이전 빌드 대비 취약점 변화율
"""

import json
import os
import sys
import re
import logging
from collections import defaultdict

try:
    from prometheus_client import (
        CollectorRegistry, Gauge, push_to_gateway
    )
except ImportError:
    import subprocess

    def _try_install():
        subprocess.run(["apt-get", "update", "-qq"], capture_output=True)
        subprocess.run(["apt-get", "install", "-y", "-q", "python3-pip"], capture_output=True)
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install",
             "prometheus_client", "--break-system-packages", "-q"],
            capture_output=True
        )
        return r.returncode == 0

    if not _try_install():
        print("[ERROR] prometheus_client 설치 실패 — 메트릭 전송 불가")
        sys.exit(1)

    from prometheus_client import (
        CollectorRegistry, Gauge, push_to_gateway
    )

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

WORKSPACE       = os.environ.get("WORKSPACE", ".")
OUTPUT_DIR      = os.path.join(WORKSPACE, "output")
PUSHGATEWAY_URL = os.environ.get("PUSHGATEWAY_URL", "pushgateway:9091")
JOB_NAME        = "supplychain_scan"

SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEV_LIST   = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

def p(filename):
    return os.path.join(OUTPUT_DIR, filename)


# =============================================================================
# 파싱 함수
# =============================================================================

def parse_trivy() -> list:
    vulns = []
    files = [
        p("trivy-result.json"),
        p("trivy-frontend-result.json"),
        p("trivy-nodemodules-result.json"),
    ]
    for fpath in files:
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            for result in data.get("Results", []):
                for v in result.get("Vulnerabilities") or []:
                    vid = v.get("VulnerabilityID", "")
                    sev = v.get("Severity", "UNKNOWN").upper()
                    if sev not in SEV_WEIGHT:
                        sev = "LOW"
                    pkg = v.get("PkgName", "unknown")
                    cvss = 0.0
                    for src in (v.get("CVSS") or {}).values():
                        cvss = max(cvss, float(src.get("V3Score") or src.get("V2Score") or 0))
                    vulns.append({
                        "tool": "trivy", "cve": vid,
                        "severity": sev, "package": pkg, "cvss": cvss
                    })
        except Exception as e:
            log.error("[Trivy] 파싱 오류 (" + fpath + "): " + str(e))

    log.info("[Trivy]  " + str(len(vulns)) + "개 파싱")
    return vulns


def parse_npm() -> list:
    vulns = []
    sev_map = {
        "critical": "CRITICAL", "high": "HIGH",
        "moderate": "MEDIUM",   "medium": "MEDIUM",
        "low": "LOW",           "info": "LOW"
    }
    files = [p("npm-audit-root.json"), p("npm-audit-frontend.json")]
    for fpath in files:
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            for pkg_name, info in (data.get("vulnerabilities") or {}).items():
                sev = sev_map.get(info.get("severity", "").lower(), "LOW")
                cve = ""
                for via in (info.get("via") or []):
                    if isinstance(via, dict):
                        cve = via.get("cve", "") or ""
                        if cve:
                            break
                vulns.append({
                    "tool": "npm", "cve": cve,
                    "severity": sev, "package": pkg_name, "cvss": 0.0
                })
        except Exception as e:
            log.error("[npm] 파싱 오류 (" + fpath + "): " + str(e))

    log.info("[npm]    " + str(len(vulns)) + "개 파싱")
    return vulns


def parse_owasp() -> list:
    vulns = []
    fpath = p("dependency-check-report.json")
    if not os.path.exists(fpath):
        log.warning("[OWASP]  파일 없음: " + fpath)
        return vulns
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        sev_map = {
            "CRITICAL": "CRITICAL", "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",     "MODERATE": "MEDIUM",
            "LOW": "LOW",           "INFO": "LOW"
        }
        for dep in data.get("dependencies", []):
            pkg = dep.get("fileName", "unknown")
            for vuln in dep.get("vulnerabilities", []):
                vid  = vuln.get("name", "")
                sev  = sev_map.get(vuln.get("severity", "").upper(), "LOW")
                cvss = 0.0
                try:
                    cvss = float(
                        vuln.get("cvssv3", {}).get("baseScore")
                        or vuln.get("cvssv2", {}).get("score")
                        or 0
                    )
                except Exception:
                    pass
                vulns.append({
                    "tool": "owasp", "cve": vid,
                    "severity": sev, "package": pkg, "cvss": cvss
                })
    except Exception as e:
        log.error("[OWASP]  파싱 오류: " + str(e))

    log.info("[OWASP]  " + str(len(vulns)) + "개 파싱")
    return vulns


def parse_semgrep() -> list:
    vulns = []
    fpath = p("semgrep-result.json")
    if not os.path.exists(fpath):
        log.warning("[Semgrep] 파일 없음: " + fpath)
        return vulns
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        sev_map = {
            "ERROR":   "HIGH",
            "WARNING": "MEDIUM",
            "INFO":    "LOW"
        }
        for finding in data.get("results", []):
            sev_raw = (finding.get("extra", {}).get("severity") or "INFO").upper()
            sev     = sev_map.get(sev_raw, "LOW")
            pkg     = finding.get("path", "unknown")
            rule    = finding.get("check_id", "")
            vulns.append({
                "tool": "semgrep", "cve": rule,
                "severity": sev, "package": pkg, "cvss": 0.0
            })
    except Exception as e:
        log.error("[Semgrep] 파싱 오류: " + str(e))

    log.info("[Semgrep] " + str(len(vulns)) + "개 파싱")
    return vulns


def load_merged_vulns() -> list:
    fpath = p("merged_vulns.json")
    if not os.path.exists(fpath):
        log.warning("[Merged] 파일 없음: " + fpath)
        return []
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception as e:
        log.error("[Merged] 로드 오류: " + str(e))
        return []


# =============================================================================
# 공격 표면 분석
# =============================================================================

def parse_attack_surface() -> dict:
    attack_surface_map = {
        'sql-injection'    : 0,
        'xss'              : 0,
        'path-traversal'   : 0,
        'open-redirect'    : 0,
        'code-injection'   : 0,
        'hardcoded-secret' : 0,
        'directory-listing': 0,
        'other'            : 0
    }

    fpath = p("semgrep-result.json")
    if not os.path.exists(fpath):
        return attack_surface_map

    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        for finding in data.get("results", []):
            rule = (finding.get("check_id") or "").lower()
            if 'sql' in rule or 'injection' in rule or 'sequelize' in rule:
                attack_surface_map['sql-injection'] += 1
            elif 'xss' in rule or 'html-format' in rule or 'raw-html' in rule:
                attack_surface_map['xss'] += 1
            elif 'path' in rule or 'traversal' in rule or 'sendfile' in rule:
                attack_surface_map['path-traversal'] += 1
            elif 'redirect' in rule:
                attack_surface_map['open-redirect'] += 1
            elif 'code' in rule or 'eval' in rule or 'string-concat' in rule:
                attack_surface_map['code-injection'] += 1
            elif 'secret' in rule or 'hardcode' in rule or 'jwt' in rule:
                attack_surface_map['hardcoded-secret'] += 1
            elif 'directory' in rule or 'listing' in rule:
                attack_surface_map['directory-listing'] += 1
            else:
                attack_surface_map['other'] += 1
    except Exception as e:
        log.error("[공격 표면] 파싱 오류: " + str(e))

    log.info("[공격 표면] " + str(attack_surface_map))
    return attack_surface_map


# =============================================================================
# 이전 빌드 대비 변화율
# =============================================================================

def calc_vuln_change(by_sev: dict) -> dict:
    prev_file = p("prev_metrics.json")
    prev_data = {}
    if os.path.exists(prev_file):
        try:
            with open(prev_file, encoding="utf-8", errors="replace") as f:
                prev_data = json.load(f)
        except Exception:
            pass

    changes = {
        "CRITICAL": by_sev.get("CRITICAL", 0) - prev_data.get("CRITICAL", 0),
        "HIGH"    : by_sev.get("HIGH",     0) - prev_data.get("HIGH",     0),
        "MEDIUM"  : by_sev.get("MEDIUM",   0) - prev_data.get("MEDIUM",   0),
        "LOW"     : by_sev.get("LOW",      0) - prev_data.get("LOW",      0),
    }

    # 현재 값 저장 (다음 빌드에서 이전값으로 사용)
    try:
        with open(prev_file, "w", encoding="utf-8") as f:
            json.dump({
                "CRITICAL": by_sev.get("CRITICAL", 0),
                "HIGH"    : by_sev.get("HIGH",     0),
                "MEDIUM"  : by_sev.get("MEDIUM",   0),
                "LOW"     : by_sev.get("LOW",      0),
            }, f)
    except Exception as e:
        log.error("[변화율] 저장 오류: " + str(e))

    log.info("[변화율] " + str(changes))
    return changes


# =============================================================================
# 집계 로직
# =============================================================================

def aggregate(all_vulns: list) -> dict:
    by_severity = defaultdict(int)
    by_tool     = defaultdict(int)
    pkg_scores  = defaultdict(lambda: {"score": 0.0, "cve": "", "severity": "LOW"})

    for v in all_vulns:
        sev  = v["severity"]
        tool = v["tool"]
        pkg  = v["package"]
        cve  = v["cve"]

        by_severity[sev]  += 1
        by_tool[tool]     += 1

        score = float(v.get("cvss") or 0)
        if score == 0.0:
            score = float(SEV_WEIGHT.get(sev, 1)) * 1.5

        if score > pkg_scores[pkg]["score"]:
            pkg_scores[pkg] = {"score": score, "cve": cve, "severity": sev}

    top10 = sorted(
        [{"package": k, **v} for k, v in pkg_scores.items()],
        key=lambda x: x["score"],
        reverse=True
    )[:10]

    return {
        "total"         : len(all_vulns),
        "by_severity"   : dict(by_severity),
        "by_tool"       : dict(by_tool),
        "top10_packages": top10,
    }


# =============================================================================
# 보안 점수 모델링
# =============================================================================

def calc_risk_score(agg: dict, semgrep_count: int) -> dict:
    by_sev = agg["by_severity"]
    total  = agg["total"]

    c = by_sev.get("CRITICAL", 0)
    h = by_sev.get("HIGH",     0)
    m = by_sev.get("MEDIUM",   0)
    l = by_sev.get("LOW",      0)

    weighted_sum    = c * 5 + h * 3 + m * 2 + l * 1
    critical_ratio  = (c / total) if total > 0 else 0.0
    critical_bonus  = critical_ratio * weighted_sum * 0.5
    semgrep_penalty = semgrep_count * 0.2

    raw_score  = weighted_sum + critical_bonus + semgrep_penalty
    MAX_RAW    = 450.0
    risk_score = min(raw_score / MAX_RAW * 100.0, 100.0)

    return {
        "risk_score"      : round(risk_score, 2),
        "critical_score"  : round(c * 5 + critical_bonus, 2),
        "high_score"      : round(h * 3, 2),
        "semgrep_score"   : round(semgrep_penalty, 2),
    }


# =============================================================================
# Confidence 분석
# =============================================================================

def calc_confidence(merged: list) -> dict:
    counts = {"single": 0, "double": 0, "triple": 0}
    for v in merged:
        sc = v.get("source_count", 1)
        if sc >= 3:
            counts["triple"] += 1
        elif sc == 2:
            counts["double"] += 1
        else:
            counts["single"] += 1
    return counts


# =============================================================================
# Prometheus 메트릭 전송
# =============================================================================

def push_metrics(agg: dict, risk: dict, confidence: dict,
                 top10: list, build_status: int,
                 attack_surface: dict, vuln_change: dict):
    registry = CollectorRegistry()

    # ── supplychain_risk_score ─────────────────────────────────────────────
    g_risk = Gauge("supplychain_risk_score", "공급망 보안 위험 점수 (0~100점)", registry=registry)
    g_risk.set(risk["risk_score"])

    # ── build_status ───────────────────────────────────────────────────────
    g_build = Gauge("build_status", "빌드 결과 (1=성공, 0=실패)", registry=registry)
    g_build.set(build_status)

    # ── total_vulnerability_count ──────────────────────────────────────────
    g_total = Gauge("total_vulnerability_count", "전체 취약점 수", registry=registry)
    g_total.set(agg["total"])

    # ── vulnerability_count{severity} ─────────────────────────────────────
    g_sev = Gauge("vulnerability_count", "severity별 취약점 수", ["severity"], registry=registry)
    for sev in SEV_LIST:
        g_sev.labels(severity=sev.lower()).set(agg["by_severity"].get(sev, 0))

    # ── tool_detection_count{tool} ────────────────────────────────────────
    g_tool = Gauge("tool_detection_count", "도구별 탐지 수", ["tool"], registry=registry)
    for tool in ["trivy", "npm", "owasp", "semgrep"]:
        g_tool.labels(tool=tool).set(agg["by_tool"].get(tool, 0))

    # ── risk_component_score{component} ───────────────────────────────────
    g_comp = Gauge("risk_component_score", "Risk Score 구성 요소별 기여도", ["component"], registry=registry)
    g_comp.labels(component="critical").set(risk["critical_score"])
    g_comp.labels(component="high").set(risk["high_score"])
    g_comp.labels(component="semgrep").set(risk["semgrep_score"])

    # ── package_risk_score{package, cve} — Top 10 ─────────────────────────
    g_pkg = Gauge("package_risk_score", "패키지별 위험 점수 (Top 10)", ["package", "cve"], registry=registry)
    for item in top10:
        pkg_raw = item["package"][:60]
        cve_raw = item["cve"][:60] if item["cve"] else "N/A"
        pkg_label = re.sub(r'[^a-zA-Z0-9_.:\-]', '_', pkg_raw)
        cve_label = re.sub(r'[^a-zA-Z0-9_.:\-]', '_', cve_raw)
        if not pkg_label:
            pkg_label = "unknown"
        if not cve_label:
            cve_label = "N/A"
        g_pkg.labels(package=pkg_label, cve=cve_label).set(item["score"])

    # ── vulnerability_confidence_count{confidence} ────────────────────────
    g_conf = Gauge("vulnerability_confidence_count", "탐지 신뢰도별 취약점 수", ["confidence"], registry=registry)
    for level in ["single", "double", "triple"]:
        g_conf.labels(confidence=level).set(confidence[level])

    # ── attack_surface_count{type} — 공격 표면 유형별 ────────────────────
    g_attack = Gauge("attack_surface_count", "Semgrep 공격 표면 유형별 취약점 수", ["type"], registry=registry)
    for attack_type, count in attack_surface.items():
        g_attack.labels(type=attack_type).set(count)

    # ── vuln_change_count{severity} — 이전 빌드 대비 변화율 ──────────────
    g_change = Gauge("vuln_change_count", "이전 빌드 대비 취약점 변화 수 (양수=증가, 음수=감소)", ["severity"], registry=registry)
    for sev, change in vuln_change.items():
        g_change.labels(severity=sev.lower()).set(change)

    # ── Pushgateway 전송 ───────────────────────────────────────────────────
    try:
        push_to_gateway(PUSHGATEWAY_URL, job=JOB_NAME, registry=registry)
        log.info("✅ Pushgateway 전송 완료 → " + PUSHGATEWAY_URL + " / job=" + JOB_NAME)
    except Exception as e:
        log.error("⚠️ Pushgateway 전송 실패: " + str(e))


# =============================================================================
# main
# =============================================================================

def main():
    log.info("=" * 60)
    log.info("  보안 결과 집계 + Prometheus Pushgateway 전송 시작")
    log.info("=" * 60)

    trivy_vulns   = parse_trivy()
    npm_vulns     = parse_npm()
    owasp_vulns   = parse_owasp()
    semgrep_vulns = parse_semgrep()
    merged_vulns  = load_merged_vulns()

    all_vulns     = trivy_vulns + npm_vulns + owasp_vulns + semgrep_vulns
    semgrep_count = len(semgrep_vulns)

    if not all_vulns:
        log.warning("⚠️ 파싱된 취약점 없음 — 메트릭 전송은 계속 진행합니다")

    agg = aggregate(all_vulns)
    log.info("[집계] 총 " + str(agg['total']) + "개")
    log.info("  severity: " + str(agg['by_severity']))
    log.info("  tool:     " + str(agg['by_tool']))

    risk = calc_risk_score(agg, semgrep_count)
    log.info("[Risk Score] " + str(risk['risk_score']) + "/100점")

    if merged_vulns:
        confidence = calc_confidence(merged_vulns)
    else:
        cve_tools = defaultdict(set)
        for v in all_vulns:
            if v["cve"]:
                cve_tools[v["cve"]].add(v["tool"])
        confidence = {"single": 0, "double": 0, "triple": 0}
        for tools in cve_tools.values():
            n = len(tools)
            if n >= 3:
                confidence["triple"] += 1
            elif n == 2:
                confidence["double"] += 1
            else:
                confidence["single"] += 1

    log.info("[Confidence] " + str(confidence))

    # 공격 표면 분석
    attack_surface = parse_attack_surface()

    # 이전 빌드 대비 변화율
    vuln_change = calc_vuln_change(agg["by_severity"])

    crit_count   = agg["by_severity"].get("CRITICAL", 0)
    build_status = 0 if (risk["risk_score"] >= 70.0 or crit_count > 0) else 1
    log.info("[Build Status] " + ("PASS" if build_status == 1 else "FAIL"))

    log.info("[Top 10 패키지]")
    for i, item in enumerate(agg["top10_packages"], 1):
        log.info("  " + str(i).rjust(2) + ". " + item['package'] + " | " + item['cve'] + " | " + item['severity'] + " | score=" + str(round(item['score'], 1)))

    push_metrics(
        agg=agg,
        risk=risk,
        confidence=confidence,
        top10=agg["top10_packages"],
        build_status=build_status,
        attack_surface=attack_surface,
        vuln_change=vuln_change
    )

    log.info("=" * 60)
    log.info("  완료")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
