# Deployment Guide

## 1. Overview

PromptGate는 AWS 환경에서 Gateway, Detection, Dashboard, PostgreSQL RDS를 각각 독립된 리소스로 배포하여 운영합니다.

각 서비스는 역할에 따라 Public Subnet과 Private Subnet으로 분리하였으며, 내부 서비스는 VPC 내부 통신만 허용하도록 구성하였습니다.

---

# 2. Deployment Architecture

Gateway EC2
        │
        ▼
Detection EC2
        │
        ▼
PostgreSQL RDS
        │
        ▼
Dashboard EC2

---

# 3. Deployment Procedure

## Step 1. AWS Network 구성

- VPC 생성
- Internet Gateway 생성 및 연결
- Route Table 구성
- Public / Private Subnet 생성

---

## Step 2. EC2 생성

다음 EC2 인스턴스를 생성하였습니다.

| Instance | Purpose |
|----------|---------|
| Gateway | AI 요청 수신 및 프록시 |
| Detection | 탐지 서비스 |
| Dashboard | 관리자 Dashboard |

---

## Step 3. Database 생성

Amazon PostgreSQL RDS를 생성하여 탐지 로그를 저장하도록 구성하였습니다.

현재 개발 환경에서는 Single-AZ 환경으로 운영하고 있으며, Database는 Private Subnet에서만 접근 가능합니다.

---

## Step 4. Security Group 구성

서비스 간 필요한 통신만 허용하도록 Security Group을 구성하였습니다.

- Client → Gateway
- Gateway → Detection
- Detection → PostgreSQL RDS
- Dashboard → PostgreSQL RDS

---

## Step 5. 서비스 배포

각 EC2 인스턴스에 서비스를 배포하고 systemd를 이용하여 서비스가 자동으로 실행되도록 구성하였습니다.

주요 서비스

- Gateway
- Detection
- Detection LogShipper
- Detection Indexer

---

# 4. Service Verification

배포 후 아래 항목을 확인하여 정상 동작 여부를 검증합니다.

- Gateway 서비스 실행 여부
- Detection API 정상 응답
- PostgreSQL RDS 연결 여부
- Dashboard 접속 여부
- 탐지 로그 저장 여부

---

# 5. Future Improvements

향후 운영 환경에서는 다음 사항을 적용할 예정입니다.

- HTTPS 인증서 자동 관리
- Auto Scaling
- Multi-AZ Database
- 모니터링 및 알림 시스템
- 실시간 Dashboard 시각화