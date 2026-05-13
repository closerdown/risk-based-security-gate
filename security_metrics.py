"""
security_metrics.py

Jenkins stage 9 이후 실행되는 보안 결과 집계 + Prometheus Pushgateway 전송 스크립트.

- 기존 stage 9의 trivy_pipe_* 메트릭은 그대로 유지 (curl로 전송)
- 이 스크립트는 supplychain_* 신규 메트릭만 추가 전송

입력 파일 (output/ 디렉토리):
  - trivy-result.json          (trivy fs 결과)
  - npm-audit-root.json        (npm audit 결과)
  - dependency-check-report.json (OWASP dependency check JSON)
  - semgrep-result.json        (semgrep 결과)
  - merged_vulns.json          (stage 6.5 병합 결과 — source_count 활용)

실행:
  python3 security_metrics.py

환경변수:
  WORKSPACE        — Jenkins workspace 경로 (기본값: 현재 디렉토리)
  PUSHGATEWAY_URL  — Pushgateway 주소 (기본값: pushgateway:9091)
"""

import json
import os
import sys
import logging
from collections import defaultdict

# ── prometheus_client 설치 확인 ───────────────────────────────────────────────
try:
    from prometheus_client import (
        CollectorRegistry, Gauge, push_to_gateway
    )
except ImportError:
    import subprocess
    subprocess.run(
        [sys.executable, "-m", "pip", "install",
         "prometheus_client", "--break-system-packages", "-q"],
        check=True
    )
    from prometheus_client import (
        CollectorRegistry, Gauge, push_to_gateway
    )

# ── 설정 ──────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

WORKSPACE       = os.environ.get("WORKSPACE", ".")
OUTPUT_DIR      = os.path.join(WORKSPACE, "output")
PUSHGATEWAY_URL = os.environ.get("PUSHGATEWAY_URL", "pushgateway:9091")
JOB_NAME        = "supplychain_scan"

# severity 가중치
SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEV_LIST   = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

def p(filename):
    """output 디렉토리 경로 조합"""
    return os.path.join(OUTPUT_DIR, filename)


# =============================================================================
# 1. 파싱 함수
# =============================================================================

def parse_trivy() -> list:
    """
    trivy-result.json / trivy-frontend-result.json / trivy-nodemodules-result.json 파싱.
    stage 5에서 생성된 파일들을 모두 읽어 합산.
    """
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
            log.error(f"[Trivy] 파싱 오류 ({fpath}): {e}")

    log.info(f"[Trivy]  {len(vulns)}개 파싱")
    return vulns


def parse_npm() -> list:
    """
    npm-audit-root.json / npm-audit-frontend.json 파싱.
    stage 3에서 생성된 파일들을 모두 읽어 합산.
    """
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
            log.error(f"[npm] 파싱 오류 ({fpath}): {e}")

    log.info(f"[npm]    {len(vulns)}개 파싱")
    return vulns


def parse_owasp() -> list:
    """
    dependency-check-report.json 파싱.
    stage 6에서 --format JSON으로 생성된 파일.
    """
    vulns = []
    fpath = p("dependency-check-report.json")
    if not os.path.exists(fpath):
        log.warning(f"[OWASP]  파일 없음: {fpath}")
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
        log.error(f"[OWASP]  파싱 오류: {e}")

    log.info(f"[OWASP]  {len(vulns)}개 파싱")
    return vulns


def parse_semgrep() -> list:
    """
    semgrep-result.json 파싱.
    stage 4에서 생성된 파일.
    severity는 semgrep의 severity → ERROR=HIGH, WARNING=MEDIUM, INFO=LOW 매핑.
    """
    vulns = []
    fpath = p("semgrep-result.json")
    if not os.path.exists(fpath):
        log.warning(f"[Semgrep] 파일 없음: {fpath}")
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
        log.error(f"[Semgrep] 파싱 오류: {e}")

    log.info(f"[Semgrep] {len(vulns)}개 파싱")
    return vulns


def load_merged_vulns() -> list:
    """
    stage 6.5에서 만든 merged_vulns.json 로드.
    source_count 필드로 confidence 계산에 활용.
    """
    fpath = p("merged_vulns.json")
    if not os.path.exists(fpath):
        log.warning(f"[Merged] 파일 없음: {fpath}")
        return []
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception as e:
        log.error(f"[Merged] 로드 오류: {e}")
        return []


# =============================================================================
# 2. 집계 로직
# =============================================================================

def aggregate(all_vulns: list) -> dict:
    """
    전체 취약점 리스트에서 메트릭 집계.
    반환:
      total          — 전체 취약점 수
      by_severity    — severity별 개수 {"CRITICAL": n, ...}
      by_tool        — tool별 개수 {"trivy": n, ...}
      top10_packages — (package, cve, severity, score) 상위 10개
    """
    by_severity = defaultdict(int)
    by_tool     = defaultdict(int)

    # package별 최고 위험도 점수 집계 (Top 10용)
    pkg_scores = defaultdict(lambda: {"score": 0.0, "cve": "", "severity": "LOW"})

    for v in all_vulns:
        sev  = v["severity"]
        tool = v["tool"]
        pkg  = v["package"]
        cve  = v["cve"]

        by_severity[sev]  += 1
        by_tool[tool]     += 1

        score = float(v.get("cvss") or 0)
        if score == 0.0:
            score = float(SEV_WEIGHT.get(sev, 1)) * 1.5  # cvss 없으면 가중치로 추정

        if score > pkg_scores[pkg]["score"]:
            pkg_scores[pkg] = {"score": score, "cve": cve, "severity": sev}

    # Top 10 패키지
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
# 3. 보안 점수 모델링
# =============================================================================

def calc_risk_score(agg: dict, semgrep_count: int) -> dict:
    """
    supplychain_risk_score 계산.

    기본 공식:
      weighted_sum = CRITICAL×5 + HIGH×3 + MEDIUM×2 + LOW×1
      critical_ratio = CRITICAL수 / 전체수
      critical_bonus = critical_ratio × weighted_sum × 0.5  (critical 비중 가중)
      semgrep_penalty = semgrep_count × 0.2

      raw_score = weighted_sum + critical_bonus + semgrep_penalty
      risk_score = min(raw_score / MAX_RAW × 100, 100)  → 100점 만점 정규화

    component별 기여도도 반환 (Grafana용).
    """
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
    # 최대값 기준: 취약점 200개 전부 CRITICAL이면 200×5×1.5 = 1500
    MAX_RAW    = 1500.0
    risk_score = min(raw_score / MAX_RAW * 100.0, 100.0)

    return {
        "risk_score"      : round(risk_score, 2),
        "critical_score"  : round(c * 5 + critical_bonus, 2),
        "high_score"      : round(h * 3, 2),
        "semgrep_score"   : round(semgrep_penalty, 2),
    }


# =============================================================================
# 4. Confidence 분석 (merged_vulns의 source_count 활용)
# =============================================================================

def calc_confidence(merged: list) -> dict:
    """
    stage 6.5 merged_vulns.json의 source_count 필드 기반.
      single  — 1개 도구에서만 탐지
      double  — 2개 도구에서 탐지
      triple  — 3개 이상 도구에서 탐지
    """
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
# 5. Prometheus 메트릭 전송
# =============================================================================

def push_metrics(agg: dict, risk: dict, confidence: dict,
                 top10: list, build_status: int):
    """
    supplychain_* 메트릭을 Pushgateway로 전송.
    기존 trivy_pipe_* 메트릭(stage 9 curl)은 건드리지 않음.
    """
    registry = CollectorRegistry()

    # ── supplychain_risk_score ─────────────────────────────────────────────
    g_risk = Gauge(
        "supplychain_risk_score",
        "공급망 보안 위험 점수 (0~100점)",
        registry=registry
    )
    g_risk.set(risk["risk_score"])

    # ── build_status ───────────────────────────────────────────────────────
    g_build = Gauge(
        "build_status",
        "빌드 결과 (1=성공, 0=실패)",
        registry=registry
    )
    g_build.set(build_status)

    # ── total_vulnerability_count ──────────────────────────────────────────
    g_total = Gauge(
        "total_vulnerability_count",
        "전체 취약점 수",
        registry=registry
    )
    g_total.set(agg["total"])

    # ── vulnerability_count{severity} ─────────────────────────────────────
    g_sev = Gauge(
        "vulnerability_count",
        "severity별 취약점 수",
        ["severity"],
        registry=registry
    )
    for sev in SEV_LIST:
        g_sev.labels(severity=sev.lower()).set(
            agg["by_severity"].get(sev, 0)
        )

    # ── tool_detection_count{tool} ────────────────────────────────────────
    g_tool = Gauge(
        "tool_detection_count",
        "도구별 탐지 수",
        ["tool"],
        registry=registry
    )
    for tool in ["trivy", "npm", "owasp", "semgrep"]:
        g_tool.labels(tool=tool).set(
            agg["by_tool"].get(tool, 0)
        )

    # ── risk_component_score{component} ───────────────────────────────────
    g_comp = Gauge(
        "risk_component_score",
        "Risk Score 구성 요소별 기여도",
        ["component"],
        registry=registry
    )
    g_comp.labels(component="critical").set(risk["critical_score"])
    g_comp.labels(component="high").set(risk["high_score"])
    g_comp.labels(component="semgrep").set(risk["semgrep_score"])

    # ── package_risk_score{package, cve} — Top 10 ─────────────────────────
    g_pkg = Gauge(
        "package_risk_score",
        "패키지별 위험 점수 (Top 10)",
        ["package", "cve"],
        registry=registry
    )
    for item in top10:
        pkg_label = item["package"][:60]   # 라벨 길이 제한
        cve_label = item["cve"][:60] if item["cve"] else "N/A"
        g_pkg.labels(package=pkg_label, cve=cve_label).set(item["score"])

    # ── vulnerability_confidence_count{confidence} ────────────────────────
    g_conf = Gauge(
        "vulnerability_confidence_count",
        "탐지 신뢰도별 취약점 수 (single/double/triple)",
        ["confidence"],
        registry=registry
    )
    for level in ["single", "double", "triple"]:
        g_conf.labels(confidence=level).set(confidence[level])

    # ── Pushgateway 전송 ───────────────────────────────────────────────────
    try:
        push_to_gateway(
            PUSHGATEWAY_URL,
            job=JOB_NAME,
            registry=registry
        )
        log.info(f"✅ Pushgateway 전송 완료 → {PUSHGATEWAY_URL} / job={JOB_NAME}")
    except Exception as e:
        log.error(f"⚠️ Pushgateway 전송 실패: {e}")


# =============================================================================
# main
# =============================================================================

def main():
    log.info("=" * 60)
    log.info("  보안 결과 집계 + Prometheus Pushgateway 전송 시작")
    log.info("=" * 60)

    # 1. 파싱
    trivy_vulns  = parse_trivy()
    npm_vulns    = parse_npm()
    owasp_vulns  = parse_owasp()
    semgrep_vulns = parse_semgrep()
    merged_vulns = load_merged_vulns()

    all_vulns    = trivy_vulns + npm_vulns + owasp_vulns + semgrep_vulns
    semgrep_count = len(semgrep_vulns)

    if not all_vulns:
        log.warning("⚠️ 파싱된 취약점 없음 — 메트릭 전송은 계속 진행합니다")

    # 2. 집계
    agg = aggregate(all_vulns)
    log.info(f"[집계] 총 {agg['total']}개")
    log.info(f"  severity: {agg['by_severity']}")
    log.info(f"  tool:     {agg['by_tool']}")

    # 3. 점수 계산
    risk = calc_risk_score(agg, semgrep_count)
    log.info(f"[Risk Score] {risk['risk_score']}/100점")
    log.info(f"  critical 기여: {risk['critical_score']}")
    log.info(f"  high 기여:     {risk['high_score']}")
    log.info(f"  semgrep 기여:  {risk['semgrep_score']}")

    # 4. Confidence 분석
    # merged_vulns 없으면 all_vulns 기반으로 tool 중복 계산
    if merged_vulns:
        confidence = calc_confidence(merged_vulns)
    else:
        # merged_vulns 없는 경우: cve 기준으로 tool 중복 직접 계산
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

    log.info(f"[Confidence] {confidence}")

    # 5. build_status 판단
    # risk_score >= 70 이거나 CRITICAL이 1개라도 있으면 실패
    crit_count   = agg["by_severity"].get("CRITICAL", 0)
    build_status = 0 if (risk["risk_score"] >= 70.0 or crit_count > 0) else 1
    log.info(f"[Build Status] {'PASS' if build_status == 1 else 'FAIL'}")

    # 6. Top 10
    log.info("[Top 10 패키지]")
    for i, item in enumerate(agg["top10_packages"], 1):
        log.info(f"  {i:2}. {item['package']} | {item['cve']} | {item['severity']} | score={item['score']:.1f}")

    # 7. 전송
    push_metrics(
        agg=agg,
        risk=risk,
        confidence=confidence,
        top10=agg["top10_packages"],
        build_status=build_status
    )

    log.info("=" * 60)
    log.info("  완료")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
