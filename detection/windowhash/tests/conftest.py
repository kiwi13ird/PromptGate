import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

TESTBED_DIR = Path(__file__).resolve().parents[3] / "test" / "testbed" / "generated"


@pytest.fixture(scope="session")
def testbed_dir() -> Path:
    if not TESTBED_DIR.exists():
        pytest.skip(f"테스트베드 디렉터리가 없습니다: {TESTBED_DIR}")
    return TESTBED_DIR


@pytest.fixture()
def tmp_db(tmp_path):
    from windowhash.store import connect

    return connect(tmp_path / "test.sqlite3")


@pytest.fixture()
def fake_redis():
    import fakeredis

    client = fakeredis.FakeRedis(decode_responses=True)
    yield client
    client.flushall()
