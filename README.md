# Security-Aware CI Pipeline

> SAST 결과를 기반으로 서비스 맥락을 반영한 위험도를 산정하고, 위험 수준에 따라 Jenkins 빌드를 자동 차단하는 Risk-Based Security Gate 프로젝트

---

## 📌 프로젝트 소개

기존 SAST 도구는 CVSS 기반으로 취약점을 평가하지만, 실제 운영 환경에서는 동일한 취약점이라도 서비스 중요도, 노출 범위, 비즈니스 영향도에 따라 우선순위가 달라질 수 있습니다.

본 프로젝트는 이러한 한계를 개선하기 위해 취약점 정보를 수집하고, 서비스 맥락을 반영한 위험도 산정 모델을 적용하여 Jenkins CI/CD 환경에서 자동 보안 검증이 가능하도록 구현하였습니다.

<br>

---

## 🤝 프로젝트 형태

**Team Project (5인)**

<br>

---

## 🎯 주요 기능

- SAST 결과 수집
- Security Metrics 계산
- Endpoint 기반 위험도 분석
- 비즈니스 중요도 반영
- Risk Score 계산
- Jenkins Security Gate
- Grafana Dashboard 시각화

<br>

---

## 🏗️ System Architecture

프로젝트는 SAST 결과 수집, Security Metrics 계산, Risk Score 산정, Jenkins Security Gate 및 Grafana 시각화까지 하나의 파이프라인으로 구성하였습니다.

<br>

<img width="751" height="450" alt="image" src="https://github.com/user-attachments/assets/2e9af83f-c41c-419e-a009-591feb574ec2" />

<br>

---

## 🚨 High-Risk Endpoint Analysis

취약 Endpoint를 분석하여 HTTP Method 분포와 비즈니스 기능별 분포를 시각화하였습니다.

이를 통해 단순 취약점 개수가 아닌 실제 영향도가 높은 기능 영역을 식별할 수 있도록 구현하였습니다.

<br>

<img width="748" height="479" alt="image" src="https://github.com/user-attachments/assets/7c8ddef7-9e28-44e9-a537-7f772afb5bc3" />

<br>

### 분석 결과 예시

- 총 43개 고위험 Endpoint 탐지
- GET / POST 요청에 위험 Endpoint 집중
- Internal, Personal 영역에 취약점 다수 분포

<br>

---

## 🔒 Jenkins Security Gate

위험 점수가 임계치를 초과할 경우 Jenkins Pipeline을 자동으로 중단하도록 구현하였습니다.

이를 통해 위험한 코드가 배포 단계로 진행되는 것을 방지할 수 있습니다.

<br>

<img width="753" height="87" alt="image" src="https://github.com/user-attachments/assets/510523ed-79b3-45ee-a261-bdd18275714d" />

<br>

### 적용 정책

```text
Risk Score > Threshold

→ Build Failed
→ Deployment Blocked
```

<br>

---

## 📊 Security Dashboard

수집된 취약점 데이터를 기반으로 위험도와 취약점 현황을 실시간으로 시각화하였습니다.

<br>

<img width="753" height="378" alt="image" src="https://github.com/user-attachments/assets/7c787dd5-cfed-4cdd-9101-6e1d4bdd1838" />

<br>

### Dashboard 주요 정보

- 전체 위험 점수
- 차단 대상 취약점 수
- 고위험 Endpoint 수
- 취약점 추이
- 취약 패키지 현황

<br>

---

## 📦 Top Risk Packages

취약 패키지와 관련 CVE를 분석하여 우선 조치가 필요한 항목을 식별하였습니다.

<br>

<img width="749" height="494" alt="image" src="https://github.com/user-attachments/assets/2ac12588-d179-4289-848f-d7210586ae07" />

<br>

### 제공 정보

- 패키지명
- CVE 정보
- Severity
- 위험 점수

<br>

---

## 📈 프로젝트 성과

- 위험도 기반 Security Gate 구현
- Jenkins 파이프라인 자동 차단 기능 구현
- 취약점 우선순위 산정 자동화
- Grafana 기반 보안 대시보드 구축
- CI/CD 환경 내 보안 검증 자동화

<br>

---

## 🛠️ 기술 스택

| Category | Stack |
|----------|--------|
| CI/CD | Jenkins, Git |
| Security | SAST, Security Metrics, CVE Analysis |
| Backend | Python |
| Visualization | Grafana |
| Environment | Docker, Linux |

<br>

---

## 🚀 향후 개선 계획

현재 프로젝트는 SAST 결과를 기반으로 위험도를 산정하고 CI/CD 환경에서 보안 게이트를 수행하는 단계까지 구현하였습니다.

프로젝트를 진행하며 정적 분석 결과만으로는 실제 취약점의 위험도를 충분히 판단하기 어렵다는 점을 확인하였습니다. 동일한 취약점이라도 서비스 환경과 실제 호출 가능성에 따라 위험도가 달라질 수 있기 때문입니다.

향후에는 다음과 같은 방향으로 개선하고자 합니다.

### DAST 연계

정적 분석 결과와 동적 분석 결과를 함께 활용하여 실제 공격 가능 여부를 검증하고 위험도 평가 정확도를 향상

### Reachability 분석 고도화

취약 코드의 실제 호출 가능성을 분석하여 오탐을 감소시키고 우선 조치 대상을 보다 정확하게 식별

### Runtime 정보 활용

실행 환경 정보를 반영하여 실제 서비스 영향도와 노출 수준을 고려한 위험도 평가 수행

### 위험도 평가 모델 개선

CVSS 중심 평가에서 벗어나 비즈니스 중요도, 노출도, 호출 가능성, 실행 결과를 종합적으로 고려하는 평가 체계로 확장
