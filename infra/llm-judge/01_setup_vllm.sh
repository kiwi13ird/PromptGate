#!/usr/bin/env bash
# LLM judge GPU 인스턴스 — vLLM + Qwen3-8B 설치
#   대상: Ubuntu 26.04 · NVIDIA L4 · ubuntu 사용자(sudo 가능)
#   실행: bash 01_setup_vllm.sh
#   결과: /opt/judge/.venv (Python 3.12 + vLLM), /opt/models/Qwen3-8B (리비전 고정),
#         /opt/judge/VERSIONS, /opt/judge/requirements.lock
#   다시 실행해도 된다(이미 된 단계는 건너뜀).
set -euo pipefail

MODEL_REPO="Qwen/Qwen3-8B"
MODEL_DIR="/opt/models/Qwen3-8B"
JUDGE_DIR="/opt/judge"
PY_VER="3.12"          # 시스템 Python 3.14에는 vLLM 휠이 없을 수 있어 별도 환경
LOG="$HOME/llm-judge-setup.log"
exec > >(tee -a "$LOG") 2>&1

[ "$(id -un)" = "ubuntu" ] || { echo "ubuntu 사용자로 실행하세요"; exit 1; }

echo "== [0] 사전 확인 $(date -Is)"
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader
df -h / | tail -1
free -h | sed -n 2p
avail=$(df --output=avail -BG / | tail -1 | tr -dc 0-9)
[ "$avail" -ge 60 ] || { echo "루트 여유 공간 ${avail}G — 60G 이상 필요"; exit 1; }

echo "== [1] 디렉터리"
sudo mkdir -p "$JUDGE_DIR/logs" /opt/models
sudo chown -R ubuntu:ubuntu "$JUDGE_DIR" /opt/models
chmod 700 "$JUDGE_DIR/logs"

echo "== [2] uv"
export PATH="$HOME/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
uv --version

echo "== [3] Python $PY_VER 가상환경"
uv python install "$PY_VER"
[ -d "$JUDGE_DIR/.venv" ] || uv venv --python "$PY_VER" "$JUDGE_DIR/.venv"
# shellcheck disable=SC1091
source "$JUDGE_DIR/.venv/bin/activate"
python --version

echo "== [4] vLLM 설치 (수 분 소요)"
uv pip install vllm huggingface_hub
uv pip freeze > "$JUDGE_DIR/requirements.lock"

echo "== [5] 모델 리비전 고정"
REV=$(python -c "from huggingface_hub import HfApi; print(HfApi().model_info('$MODEL_REPO').sha)")
echo "revision: $REV"

echo "== [6] 모델 다운로드 (약 16GB)"
python -c "
from huggingface_hub import snapshot_download
snapshot_download(repo_id='$MODEL_REPO', revision='$REV', local_dir='$MODEL_DIR')
"
du -sh "$MODEL_DIR"

echo "== [7] 버전 기록"
python - "$MODEL_REPO" "$REV" "$MODEL_DIR" > "$JUDGE_DIR/VERSIONS" <<'PY'
import datetime, platform, subprocess, sys
import torch, vllm
repo, rev, mdir = sys.argv[1:4]
drv = subprocess.run(["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"],
                     capture_output=True, text=True).stdout.strip()
print(f"recorded_at={datetime.datetime.now().isoformat(timespec='seconds')}")
print(f"python={platform.python_version()}")
print(f"vllm={vllm.__version__}")
print(f"torch={torch.__version__}")
print(f"torch_cuda={torch.version.cuda}")
print(f"driver={drv}")
print(f"model_repo={repo}")
print(f"model_revision={rev}")
print(f"model_dir={mdir}")
PY
cat "$JUDGE_DIR/VERSIONS"
echo "== 완료. 다음: bash 02_install_service.sh   (전체 로그: $LOG)"
