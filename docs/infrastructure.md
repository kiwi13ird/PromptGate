# AWS Infrastructure

## 1. Overview

PromptGate는 AWS 기반의 AI Security Gateway로, Gateway, Detection, Dashboard, PostgreSQL RDS를 각각 독립된 리소스로 구성하여 운영하고 있습니다.

서비스의 역할에 따라 Public Subnet과 Private Subnet을 분리하였으며, 외부 접근이 필요한 서비스와 내부 보안 서비스를 구분하여 네트워크를 설계하였습니다.

이를 통해 서비스의 보안성과 유지보수성을 높이고, 내부 탐지 서버와 데이터베이스가 외부에 직접 노출되지 않도록 구성하였습니다.

---

# 2. VPC Configuration

| Resource | Value |
|-----------|-------|
| AWS Region | ap-northeast-2 (Seoul) |
| VPC Name | promptgate-vpc |
| CIDR Block | 10.0.0.0/16 |

PromptGate의 모든 리소스는 하나의 VPC 내부에서 동작하며, 서비스 간 통신은 VPC 내부 네트워크를 이용합니다.

---

# 3. Subnet Configuration

서비스의 역할에 따라 Public Subnet과 Private Subnet을 분리하여 구성하였습니다.

## Public Subnet

| Name | CIDR | Resource | Purpose |
|------|------|----------|---------|
| gateway-public-subnet | 10.0.1.0/24 | Gateway EC2 | 사용자 요청 수신 및 프록시 |
| dashboard-public-subnet | 10.0.4.0/24 | Dashboard EC2 | 관리자 Dashboard |

Gateway는 외부 사용자의 AI 요청을 최초로 수신하는 진입점이므로 Public Subnet에 배치하였습니다.

Dashboard는 관리자가 웹 브라우저를 통해 시스템 상태와 탐지 결과를 조회해야 하므로 Public Subnet에 배치하였습니다. 단, Security Group을 통해 허용된 포트와 접근만 가능하도록 제한하여 운영합니다.

---

## Reserved Subnet

| Name | CIDR | Status |
|------|------|--------|
| reserved-subnet | 10.0.2.0/24 | Reserved for Future Expansion |

현재는 사용하지 않는 서브넷이며, 향후 서비스 확장 또는 신규 리소스 배치를 위해 예약해두었습니다.

---

## Private Subnet

| Name | CIDR | Resource | Purpose |
|------|------|----------|---------|
| detection-private-subnet | 10.0.3.0/24 | Detection EC2 | 기밀문서 및 개인정보 탐지 |
| db-private-subnet-a | 10.0.5.0/24 | PostgreSQL RDS | Database |
| db-private-subnet-b | 10.0.6.0/24 | PostgreSQL RDS | Database Subnet Group |

Detection 서버와 PostgreSQL RDS는 외부에서 직접 접근할 필요가 없는 내부 서비스입니다.

Gateway를 통해서만 Detection 서버에 접근할 수 있으며, Detection 서버만 PostgreSQL RDS에 탐지 로그를 저장하도록 구성하여 외부 노출을 최소화하였습니다.

---

# 4. EC2 Configuration

| Instance | Subnet | Primary Role |
|-----------|--------|--------------|
| Gateway EC2 | Public | Reverse Proxy 및 AI 요청 전달 |
| Detection EC2 | Private | Window Hash / Signature 기반 탐지 |
| Dashboard EC2 | Public | 관리자 Dashboard 및 로그 조회 |

각 서비스는 독립된 EC2 인스턴스로 구성하여 역할을 분리하였으며, 서비스별 유지보수 및 확장이 가능하도록 설계하였습니다.

---

# 5. Database Configuration

| Item | Value |
|------|-------|
| Engine | PostgreSQL |
| Purpose | Detection Log Storage |
| Deployment | Single-AZ |
| Network | Private Subnet |

Detection 서버에서 생성된 탐지 로그는 PostgreSQL RDS에 저장되며, Dashboard는 저장된 로그를 조회하여 운영 화면에 표시합니다.

현재는 개발 환경이므로 비용을 고려하여 Single-AZ 환경으로 구성하였으며, 운영 환경에서는 Multi-AZ 구성을 고려할 수 있습니다.

---

# 6. Security Group

| Source | Destination | Port | Purpose |
|---------|-------------|------|---------|
| Internet | Gateway EC2 | HTTPS (443) | 사용자 AI 요청 |
| Internet | Dashboard EC2 | HTTPS (443) | 관리자 Dashboard |
| Gateway EC2 | Detection EC2 | Detection API (실제 포트) | 탐지 요청 전달 |
| Detection EC2 | PostgreSQL RDS | PostgreSQL (5432) | 탐지 로그 저장 |
| Dashboard EC2 | PostgreSQL RDS | PostgreSQL (5432) | 탐지 로그 및 통계 조회 |

각 서비스는 필요한 통신만 허용하도록 Security Group을 구성하였으며, Detection 서버와 PostgreSQL RDS는 외부에서 직접 접근할 수 없도록 제한하였습니다.

---

# 7. Infrastructure Layout

| Layer | Resource | Description |
|--------|----------|-------------|
| Client Layer | User PC | AI 서비스 이용 |
| Proxy Layer | Gateway EC2 | 사용자 요청 수신 및 Detection 전달 |
| Detection Layer | Detection EC2 | Window Hash 및 Signature 기반 탐지 |
| Data Layer | PostgreSQL RDS | 탐지 로그 저장 |
| Management Layer | Dashboard EC2 | 운영 현황 및 로그 조회 |

---

# 8. Infrastructure Design

PromptGate는 서비스의 역할에 따라 네트워크를 분리하여 보안성과 운영 효율성을 높이는 것을 목표로 설계하였습니다.

- Gateway는 외부 요청을 처리하기 위해 Public Subnet에 배치하였습니다.
- Dashboard는 관리자가 웹 브라우저를 통해 접속해야 하므로 Public Subnet에 배치하였습니다.
- Detection 서버는 Gateway를 통해서만 접근 가능한 내부 서비스이므로 Private Subnet에 배치하였습니다.
- PostgreSQL RDS는 Detection 및 Dashboard만 접근할 수 있도록 구성하여 데이터베이스의 외부 노출을 차단하였습니다.
- 향후 서비스 확장을 고려하여 Reserved Subnet을 별도로 구성하였습니다.