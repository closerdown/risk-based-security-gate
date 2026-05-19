"""
security_metrics.py
Jenkins stage 10에서 실행되는 보안 결과 집계 + Prometheus Pushgateway 전송 스크립트.

Security Gate 정책:
  0~39   → PASS
  40~59  → WARN
  60~79  → HIGH RISK
  80+    → CRITICAL BLOCK
"""

import json
import os
import sys
import re
import logging
from collections import defaultdict

try:
    from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
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
        print("[ERROR] prometheus_client 설치 실패")
        sys.exit(1)
    from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

WORKSPACE       = os.environ.get("WORKSPACE", ".")
OUTPUT_DIR      = os.path.join(WORKSPACE, "output")
PUSHGATEWAY_URL = os.environ.get("PUSHGATEWAY_URL", "pushgateway:9091")
JOB_NAME        = "supplychain_scan"

SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEV_LIST   = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

THRESHOLD_CRITICAL_BLOCK = 80
THRESHOLD_HIGH_RISK      = 60
THRESHOLD_WARN           = 40


def p(filename):
    return os.path.join(OUTPUT_DIR, filename)


def safe_cvss(v):
    val = v.get("cvss")
    if val is None:
        return None
    try:
        f = float(val)
        return f if f > 0 else None
    except (TypeError, ValueError):
        return None


def cvss_for_score(v):
    val = safe_cvss(v)
    if val is not None:
        return val
    sev = v.get("severity", "LOW").upper()
    return float(SEV_WEIGHT.get(sev, 1)) * 1.5


def parse_trivy() -> list:
    vulns = []
    files = [p("trivy-result.json"), p("trivy-frontend-result.json"), p("trivy-nodemodules-result.json")]
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
                    cvss = None
                    for src in (v.get("CVSS") or {}).values():
                        val = float(src.get("V3Score") or src.get("V2Score") or 0)
                        if val > 0:
                            cvss = max(cvss, val) if cvss is not None else val
                    vulns.append({"tool": "trivy", "cve": vid, "severity": sev, "package": pkg, "cvss": cvss})
        except Exception as e:
            log.error("[Trivy] 파싱 오류 (" + fpath + "): " + str(e))
    log.info("[Trivy]  " + str(len(vulns)) + "개 파싱")
    return vulns


def parse_npm() -> list:
    vulns = []
    sev_map = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "medium": "MEDIUM", "low": "LOW", "info": "LOW"}
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
                cvss = None
                for via in (info.get("via") or []):
                    if isinstance(via, dict):
                        cve = via.get("cve", "") or ""
                        raw = float((via.get("cvss") or {}).get("score") or 0)
                        if raw > 0:
                            cvss = raw
                        if cve:
                            break
                vulns.append({"tool": "npm", "cve": cve, "severity": sev, "package": pkg_name, "cvss": cvss})
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
        sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM", "LOW": "LOW", "INFO": "LOW"}
        for dep in data.get("dependencies", []):
            pkg = dep.get("fileName", "unknown")
            for vuln in dep.get("vulnerabilities", []):
                vid = vuln.get("name", "")
                if not vid:
                    continue
                sev = sev_map.get(vuln.get("severity", "").upper(), "LOW")
                cvss = None
                for key in ["cvssv3", "cvssV3", "cvss3"]:
                    cvssv3 = vuln.get(key) or {}
                    for score_key in ["baseScore", "score"]:
                        val = cvssv3.get(score_key)
                        if val is not None:
                            try:
                                cvss = float(val)
                                if cvss > 0:
                                    break
                            except (ValueError, TypeError):
                                pass
                    if cvss and cvss > 0:
                        break
                if not cvss:
                    for key in ["cvssv2", "cvssV2", "cvss2"]:
                        cvssv2 = vuln.get(key) or {}
                        for score_key in ["score", "baseScore"]:
                            val = cvssv2.get(score_key)
                            if val is not None:
                                try:
                                    cvss = float(val)
                                    if cvss > 0:
                                        break
                                except (ValueError, TypeError):
                                    pass
                        if cvss and cvss > 0:
                            break
                if not cvss:
                    SEV_FALLBACK = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.0}
                    cvss = SEV_FALLBACK.get(sev, 5.0)
                vulns.append({"tool": "owasp", "cve": vid, "severity": sev, "package": pkg, "cvss": cvss})
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
        sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        for finding in data.get("results", []):
            sev_raw = (finding.get("extra", {}).get("severity") or "INFO").upper()
            sev     = sev_map.get(sev_raw, "LOW")
            pkg     = finding.get("path", "unknown")
            rule    = finding.get("check_id", "")
            vulns.append({"tool": "semgrep", "cve": rule, "severity": sev, "package": pkg, "cvss": None})
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


def load_business_risk() -> list:
    fpath = p("business-risk-result.json")
    if not os.path.exists(fpath):
        return []
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception as e:
        log.error("[BizRisk] 로드 오류: " + str(e))
        return []


def load_swagger_high_risk() -> int:
    fpath = p("swagger-analysis.json")
    if not os.path.exists(fpath):
        return 0
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        return len(data.get("summary", {}).get("high_risk", []))
    except Exception as e:
        log.error("[Swagger] 로드 오류: " + str(e))
        return 0


def load_cvss_comparison() -> dict:
    fpath = p("cvss-comparison.json")
    if not os.path.exists(fpath):
        log.warning("[CVSSComp] 파일 없음 — 스킵")
        return {"upgraded": [], "downgraded": [], "summary": {"upgraded_count": 0, "downgraded_count": 0}}
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception as e:
        log.error("[CVSSComp] 로드 오류: " + str(e))
        return {"upgraded": [], "downgraded": [], "summary": {"upgraded_count": 0, "downgraded_count": 0}}


def parse_attack_surface() -> dict:
    attack_surface_map = {
        "sql-injection": 0, "xss": 0, "path-traversal": 0, "open-redirect": 0,
        "code-injection": 0, "hardcoded-secret": 0, "directory-listing": 0, "other": 0
    }
    fpath = p("semgrep-result.json")
    if not os.path.exists(fpath):
        return attack_surface_map
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        for finding in data.get("results", []):
            rule = (finding.get("check_id") or "").lower()
            if "sql" in rule or "injection" in rule or "sequelize" in rule:
                attack_surface_map["sql-injection"] += 1
            elif "xss" in rule or "html-format" in rule or "raw-html" in rule:
                attack_surface_map["xss"] += 1
            elif "path" in rule or "traversal" in rule or "sendfile" in rule:
                attack_surface_map["path-traversal"] += 1
            elif "redirect" in rule:
                attack_surface_map["open-redirect"] += 1
            elif "code" in rule or "eval" in rule or "string-concat" in rule:
                attack_surface_map["code-injection"] += 1
            elif "secret" in rule or "hardcode" in rule or "jwt" in rule:
                attack_surface_map["hardcoded-secret"] += 1
            elif "directory" in rule or "listing" in rule:
                attack_surface_map["directory-listing"] += 1
            else:
                attack_surface_map["other"] += 1
    except Exception as e:
        log.error("[공격 표면] 파싱 오류: " + str(e))
    log.info("[공격 표면] " + str(attack_surface_map))
    return attack_surface_map


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
    try:
        with open(prev_file, "w", encoding="utf-8") as f:
            json.dump({k: by_sev.get(k, 0) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}, f)
    except Exception as e:
        log.error("[변화율] 저장 오류: " + str(e))
    log.info("[변화율] " + str(changes))
    return changes


def aggregate(all_vulns: list) -> dict:
    by_severity = defaultdict(int)
    by_tool     = defaultdict(int)
    pkg_scores  = defaultdict(lambda: {"score": 0.0, "cve": "", "severity": "LOW"})
    for v in all_vulns:
        sev  = v["severity"]
        tool = v["tool"]
        pkg  = v["package"]
        cve  = v["cve"]
        by_severity[sev] += 1
        by_tool[tool]    += 1
        score = cvss_for_score(v)
        if score > pkg_scores[pkg]["score"]:
            pkg_scores[pkg] = {"score": score, "cve": cve, "severity": sev}
    all_packages = sorted(
        [{"package": k, **v} for k, v in pkg_scores.items()],
        key=lambda x: x["score"], reverse=True
    )
    return {"total": len(all_vulns), "by_severity": dict(by_severity), "by_tool": dict(by_tool), "top10_packages": all_packages}


def calc_risk_score(agg: dict, semgrep_count: int, swagger_high_risk: int = 0, biz_scores: list = None) -> dict:
    by_sev = agg["by_severity"]
    c = by_sev.get("CRITICAL", 0)
    h = by_sev.get("HIGH",     0)
    m = by_sev.get("MEDIUM",   0)

    if biz_scores:
        sorted_scores = sorted([float(v.get("finalScore", 0)) for v in biz_scores], reverse=True)
        block_scores  = sorted([float(v.get("finalScore", 0)) for v in biz_scores if float(v.get("finalScore", 0)) >= 14.0], reverse=True)
        warn_scores   = sorted([float(v.get("finalScore", 0)) for v in biz_scores if 8.0 <= float(v.get("finalScore", 0)) < 14.0], reverse=True)
        if block_scores:
            block_avg = sum(block_scores) / len(block_scores)
            warn_avg  = sum(warn_scores[:3]) / min(len(warn_scores), 3) if warn_scores else 0.0
            top_avg   = block_avg * 0.7 + warn_avg * 0.3
        elif warn_scores:
            top_avg = sum(warn_scores[:3]) / min(len(warn_scores), 3)
        else:
            top_avg = sorted_scores[0] if sorted_scores else 0.0
        top3_avg = top_avg
    else:
        top3_avg = 0.0

    quality_score  = min((top3_avg / 20.0) * 70.0, 70.0)
    vuln_scale     = (c * 1.0) + (h * 0.2) + (m * 0.05)
    endpoint_scale = swagger_high_risk * 0.3
    scale_score    = min(vuln_scale + endpoint_scale, 30.0)
    risk_score     = min(quality_score + scale_score, 100.0)

    COLOR_RESET = "\033[0m"
    if risk_score >= THRESHOLD_CRITICAL_BLOCK:
        grade = "CRITICAL_BLOCK"; status = "CRITICAL BLOCK"; action = "BLOCK"
        reason = "Critical supply chain risk detected. Immediate remediation required."
        color  = "\033[1;31m"
    elif risk_score >= THRESHOLD_HIGH_RISK:
        grade = "HIGH_RISK"; status = "HIGH RISK"; action = "BLOCK"
        reason = "Supply chain risk exceeded deployment threshold."
        color  = "\033[0;31m"
    elif risk_score >= THRESHOLD_WARN:
        grade = "WARN"; status = "WARN"; action = "ALLOW"
        reason = "Elevated risk detected. Security review recommended before release."
        color  = "\033[0;33m"
    else:
        grade = "PASS"; status = "PASS"; action = "ALLOW"
        reason = "Supply chain risk within acceptable range."
        color  = "\033[0;32m"

    log.info("")
    log.info("=" * 55)
    log.info(color + "  Risk Score : " + str(round(risk_score, 1)) + "/100" + COLOR_RESET)
    log.info(color + "  Status     : " + status + COLOR_RESET)
    log.info(color + "  Action     : " + action + COLOR_RESET)
    log.info(color + "  Reason     : " + reason + COLOR_RESET)
    log.info("=" * 55)
    log.info("")

    return {
        "risk_score": round(risk_score, 1), "quality_score": round(quality_score, 1),
        "scale_score": round(scale_score, 1), "top3_avg": round(top3_avg, 2),
        "critical_score": round(c * 1.0, 1), "high_score": round(h * 0.2, 1),
        "semgrep_score": 0.0, "grade": grade, "status": status, "action": action, "reason": reason,
    }


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


def push_metrics(agg, risk, confidence, top10, build_status,
                 attack_surface, vuln_change,
                 total_raw=0, swagger_high_risk=0, merged_vulns=None,
                 biz_scores=None, cvss_comparison=None):
    registry = CollectorRegistry()

    Gauge("supplychain_risk_score", "공급망 보안 위험 점수 (0~100점)", registry=registry).set(risk["risk_score"])
    Gauge("build_status", "빌드 결과 (1=성공, 0=실패)", registry=registry).set(build_status)
    Gauge("total_vulnerability_count", "전체 취약점 수 (중복 포함)", registry=registry).set(total_raw or agg["total"])

    g_sev = Gauge("vulnerability_count", "severity별 취약점 수", ["severity"], registry=registry)
    for sev in SEV_LIST:
        g_sev.labels(severity=sev.lower()).set(agg["by_severity"].get(sev, 0))

    g_tool = Gauge("tool_detection_count", "도구별 탐지 수", ["tool"], registry=registry)
    for tool in ["trivy", "npm", "owasp", "semgrep"]:
        g_tool.labels(tool=tool).set(agg["by_tool"].get(tool, 0))

    g_comp = Gauge("risk_component_score", "Risk Score 구성 요소별 기여도", ["component"], registry=registry)
    g_comp.labels(component="quality").set(risk["quality_score"])
    g_comp.labels(component="scale").set(risk["scale_score"])
    g_comp.labels(component="top3_avg").set(risk["top3_avg"])

    g_raw = Gauge("raw_detection_count", "원본 탐지 수치", ["type"], registry=registry)
    for t, k in [("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW")]:
        g_raw.labels(type=t).set(agg["by_severity"].get(k, 0))
    g_raw.labels(type="semgrep").set(agg["by_tool"].get("semgrep", 0))
    g_raw.labels(type="endpoint_high_risk").set(swagger_high_risk)

    g_pkg = Gauge("package_risk_score", "패키지별 위험 점수", ["package", "cve", "severity"], registry=registry)
    for item in top10:
        pkg = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(item["package"])[:60]) or "unknown"
        cve = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(item["cve"])[:60]) if item["cve"] else "N_A"
        sev = item.get("severity", "UNKNOWN").upper()
        sev = sev if sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "UNKNOWN"
        g_pkg.labels(package=pkg, cve=cve, severity=sev).set(item["score"])

    # ── 신규: CVE 상세 — connectedApi, semgrepFile 포함 ─────────────────────
    if merged_vulns:
        biz_map = {}
        if biz_scores:
            for b in biz_scores:
                cve_key = str(b.get("cve", "")).strip()
                if cve_key:
                    biz_map[cve_key] = b

        g_vuln = Gauge("vuln_detail_score", "CVE별 전체 취약점 목록",
                       ["vuln_id", "package", "severity", "source",
                        "reachability", "biz_score", "final_score",
                        "connected_api", "semgrep_file"],   # 신규 label
                       registry=registry)

        for v in merged_vulns:
            vid      = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("vuln_id", "N/A"))[:80]) or "N_A"
            pkg      = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("package", "unknown"))[:60]) or "unknown"
            sev      = v.get("severity", "LOW").upper()
            src      = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("source", "unknown"))[:30]) or "unknown"
            sev      = sev if sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "UNKNOWN"
            cvss_val = safe_cvss(v)
            if cvss_val is None:
                cvss_val = 0  # Grafana 표에서 0으로 표시 (-1은 필터링 안됨)

            raw_vid  = str(v.get("vuln_id", "")).strip()
            biz      = biz_map.get(raw_vid)
            reach    = str(round(float(biz.get("reachability", 1.0)), 1)) if biz else "-"
            bscore   = str(int(biz.get("bizScore", 0)))                    if biz else "-"
            fscore   = str(round(float(biz.get("finalScore", 0.0)), 2))    if biz else "-"

            # connectedApis — 첫 번째 항목만 label에 (Prometheus label 길이 제한)
            apis     = biz.get("connectedApis", []) if biz else []
            conn_api = re.sub(r"[^a-zA-Z0-9_.:\-/]", "_", str(apis[0])[:80]) if apis else "-"

            # semgrepFiles — 첫 번째 항목만
            sfiles   = biz.get("semgrepFiles", []) if biz else []
            sem_file = re.sub(r"[^a-zA-Z0-9_.:\-/]", "_", str(sfiles[0])[:80]) if sfiles else "-"

            g_vuln.labels(
                vuln_id=vid, package=pkg, severity=sev, source=src,
                reachability=reach, biz_score=bscore, final_score=fscore,
                connected_api=conn_api, semgrep_file=sem_file
            ).set(cvss_val)

        log.info("[CVE 전체 목록] " + str(len(merged_vulns)) + "개 전송")

    g_conf = Gauge("vulnerability_confidence_count", "탐지 신뢰도별 취약점 수", ["confidence"], registry=registry)
    for level in ["single", "double", "triple"]:
        g_conf.labels(confidence=level).set(confidence[level])

    g_attack = Gauge("attack_surface_count", "Semgrep 공격 표면 유형별", ["type"], registry=registry)
    for t, cnt in attack_surface.items():
        g_attack.labels(type=t).set(cnt)

    g_change = Gauge("vuln_change_count", "이전 빌드 대비 변화", ["severity"], registry=registry)
    for sev, change in vuln_change.items():
        g_change.labels(severity=sev.lower()).set(change)

    # ── CVSS vs Business Risk 비교 메트릭 ────────────────────────────────────
    if cvss_comparison:
        summary          = cvss_comparison.get("summary", {})
        upgraded_count   = summary.get("upgraded_count", 0)
        downgraded_count = summary.get("downgraded_count", 0)

        Gauge("cvss_comparison_upgraded_count",
              "CVSS로는 못 잡는데 Business Risk로 추가 Block한 취약점 수",
              registry=registry).set(upgraded_count)
        Gauge("cvss_comparison_downgraded_count",
              "CVSS는 Block이나 Business Risk로 Pass 처리한 취약점 수 (과잉 차단 방지)",
              registry=registry).set(downgraded_count)

        g_upgraded = Gauge("cvss_upgraded_detail",
                           "CVSS 대비 Business Risk로 추가 탐지된 취약점 상세",
                           ["vuln_id", "package", "cvss_gate", "biz_gate",
                            "biz_category", "final_score", "connected_api"],
                           registry=registry)
        for v in (cvss_comparison.get("upgraded") or []):
            vid  = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("cve", "N/A"))[:80]) or "N_A"
            pkg  = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("pkg", "unknown"))[:60]) or "unknown"
            cat  = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("bizCat", "unknown"))[:30]) or "unknown"
            apis = v.get("connectedApis", [])
            conn = re.sub(r"[^a-zA-Z0-9_.:\-/]", "_", str(apis[0])[:80]) if apis else "-"
            g_upgraded.labels(
                vuln_id=vid, package=pkg,
                cvss_gate=str(v.get("cvssGate", "")),
                biz_gate=str(v.get("bizGate", "")),
                biz_category=cat,
                final_score=str(round(float(v.get("final", 0)), 2)),
                connected_api=conn
            ).set(float(v.get("cvss", 0)))

        g_downgraded = Gauge("cvss_downgraded_detail",
                             "CVSS Block → Business Risk Pass (과잉 차단 방지) 상세",
                             ["vuln_id", "package", "cvss_gate", "biz_gate", "biz_category", "final_score"],
                             registry=registry)
        for v in (cvss_comparison.get("downgraded") or []):
            vid = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("cve", "N/A"))[:80]) or "N_A"
            pkg = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("pkg", "unknown"))[:60]) or "unknown"
            cat = re.sub(r"[^a-zA-Z0-9_.:\-]", "_", str(v.get("bizCat", "unknown"))[:30]) or "unknown"
            g_downgraded.labels(
                vuln_id=vid, package=pkg,
                cvss_gate=str(v.get("cvssGate", "")),
                biz_gate=str(v.get("bizGate", "")),
                biz_category=cat,
                final_score=str(round(float(v.get("final", 0)), 2))
            ).set(float(v.get("cvss", 0)))

        log.info("[CVSS 비교] 추가 탐지: " + str(upgraded_count) +
                 "개 / 과잉 차단 방지: " + str(downgraded_count) + "개")

    try:
        push_to_gateway(PUSHGATEWAY_URL, job=JOB_NAME, registry=registry)
        log.info("Pushgateway 전송 완료 → " + PUSHGATEWAY_URL)
    except Exception as e:
        log.error("Pushgateway 전송 실패: " + str(e))


def main():
    log.info("=" * 60)
    log.info("  보안 결과 집계 + Prometheus Pushgateway 전송 시작")
    log.info("=" * 60)

    trivy_vulns       = parse_trivy()
    npm_vulns         = parse_npm()
    owasp_vulns       = parse_owasp()
    semgrep_vulns     = parse_semgrep()
    merged_vulns      = load_merged_vulns()
    biz_risk          = load_business_risk()
    swagger_high_risk = load_swagger_high_risk()
    cvss_comparison   = load_cvss_comparison()
    semgrep_count     = len(semgrep_vulns)

    all_vulns = trivy_vulns + npm_vulns + owasp_vulns + semgrep_vulns
    agg_all   = aggregate(all_vulns)

    if merged_vulns:
        merged_for_score = []
        for v in merged_vulns:
            sev = v.get("severity", "LOW").upper()
            merged_for_score.append({
                "tool": v.get("source", "merged"), "cve": v.get("vuln_id", ""),
                "severity": sev, "package": v.get("package", "unknown"), "cvss": safe_cvss(v),
            })
        agg = aggregate(merged_for_score)
    else:
        agg = agg_all

    agg["by_tool"] = agg_all["by_tool"]

    risk = calc_risk_score(agg=agg, semgrep_count=semgrep_count,
                           swagger_high_risk=swagger_high_risk, biz_scores=biz_risk)

    confidence     = calc_confidence(merged_vulns) if merged_vulns else {"single": 0, "double": 0, "triple": 0}
    attack_surface = parse_attack_surface()
    vuln_change    = calc_vuln_change(agg["by_severity"])
    block_count    = sum(1 for v in biz_risk if float(v.get("finalScore", 0)) >= 14.0)
    build_status   = 0 if (risk["action"] == "BLOCK" or block_count > 0) else 1

    log.info("[Build Status] " + ("FAIL" if build_status == 0 else "PASS") +
             " | score=" + str(risk["risk_score"]) +
             " | status=" + risk["status"] +
             " | action=" + risk["action"])

    push_metrics(
        agg=agg, risk=risk, confidence=confidence,
        top10=agg["top10_packages"], build_status=build_status,
        attack_surface=attack_surface, vuln_change=vuln_change,
        total_raw=agg_all["total"], swagger_high_risk=swagger_high_risk,
        merged_vulns=merged_vulns, biz_scores=biz_risk,
        cvss_comparison=cvss_comparison
    )

    log.info("=" * 60)
    log.info("  완료")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
