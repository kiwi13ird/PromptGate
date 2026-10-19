#!/usr/bin/env bash
# judge-vllm systemd 서비스 등록·기동 후 준비될 때까지 대기
#   실행: bash 02_install_service.sh   (01_setup_vllm.sh 이후)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -x /opt/judge/.venv/bin/vllm ] || { echo "vLLM이 없습니다. 01_setup_vllm.sh 먼저"; exit 1; }
[ -f /opt/models/Qwen3-8B/config.json ] || { echo "모델이 없습니다. 01_setup_vllm.sh 먼저"; exit 1; }

sudo cp "$HERE/judge-vllm.service" /etc/systemd/system/judge-vllm.service
sudo systemctl daemon-reload
sudo systemctl enable --now judge-vllm

echo "모델 적재 대기 (최대 15분)..."
for i in $(seq 1 180); do
  if curl -sf -m 3 http://127.0.0.1:8000/v1/models >/dev/null; then
    echo "준비 완료 (${i}회 x 5초)"
    curl -s http://127.0.0.1:8000/v1/models; echo
    nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader
    free -h | sed -n 2p
    echo "다음: bash 03_smoke_test.sh"
    exit 0
  fi
  if ! systemctl is-active --quiet judge-vllm; then
    echo "서비스가 멈췄습니다. 최근 로그:"
    sudo journalctl -u judge-vllm -n 40 --no-pager
    echo "※ 로그에 'Killed' 또는 메모리 부족이 보이면 RAM 부족 → 인스턴스 중지 후 g6.2xlarge로 타입 변경"
    exit 1
  fi
  sleep 5
done
echo "15분 안에 준비되지 않았습니다. 최근 로그:"
sudo journalctl -u judge-vllm -n 40 --no-pager
exit 1
