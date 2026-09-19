#!/usr/bin/env bash
# RDS PostgreSQL 초기화 — Detection EC2에서 1회 실행.
#   1) dlp 데이터베이스 생성  2) schema.sql 적용(표·트리거·역할)  3) 서비스 역할 비밀번호 발급 → /opt/detection/pg.env (0600)
# 사용: PGHOST=<endpoint> PGPASSWORD=<master pw> bash bootstrap.sh
# 비밀번호는 인자·파일이 아니라 환경변수로만 받는다(셸 히스토리·로그에 남지 않게 앞에 공백을 두고 실행하거나 read -s 사용).
set -euo pipefail

: "${PGHOST:?PGHOST(엔드포인트)가 필요합니다}"
: "${PGPASSWORD:?PGPASSWORD(마스터 비밀번호)가 필요합니다}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"
DB="${DLP_DB:-dlp}"
SCHEMA="$(dirname "$0")/schema.sql"
ENV_OUT="${DLP_ENV_OUT:-/opt/detection/pg.env}"
export PGPORT PGUSER PGSSLMODE=require

echo "== 1. 접속 확인 ($PGHOST:$PGPORT as $PGUSER)"
psql -h "$PGHOST" -d postgres -Atc "select version();"

echo "== 2. 데이터베이스 $DB"
if psql -h "$PGHOST" -d postgres -Atc "select 1 from pg_database where datname='$DB'" | grep -q 1; then
  echo "   이미 있음"
else
  psql -h "$PGHOST" -d postgres -c "create database $DB encoding 'UTF8';"
fi

echo "== 3. 스키마 적용 ($SCHEMA)"
psql -h "$PGHOST" -d "$DB" -v ON_ERROR_STOP=1 -f "$SCHEMA"

echo "== 4. 서비스 역할 비밀번호 발급 → $ENV_OUT"
gen() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32; }
umask 077
{
  echo "PGHOST=$PGHOST"
  echo "PGPORT=$PGPORT"
  echo "PGDATABASE=$DB"
  for role in dlp_indexer dlp_detection dlp_judge dlp_dashboard; do
    pw="$(gen)"
    psql -h "$PGHOST" -d "$DB" -qc "alter role $role with password '$pw';"
    echo "PG_${role^^}_PASSWORD=$pw"
  done
} > "$ENV_OUT"
chmod 600 "$ENV_OUT"

echo "== 5. 확인"
psql -h "$PGHOST" -d "$DB" -Atc "select table_name from information_schema.tables where table_schema='public' order by 1;"
psql -h "$PGHOST" -d "$DB" -Atc "select rolname from pg_roles where rolname like 'dlp_%' order by 1;"
echo "완료. 역할 비밀번호는 $ENV_OUT 에만 있다(마스터 비밀번호는 기록하지 않음)."
