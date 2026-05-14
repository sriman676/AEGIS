import asyncio
import time
import sys
import os
import os.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport
from src.main import app, limiter
from src.security import AEGIS_API_KEY
import tempfile
import subprocess

client = TestClient(app)
client.headers.update({"X-AEGIS-Key": AEGIS_API_KEY})

def setup_mock_repo():
    repo_dir = tempfile.mkdtemp()

    # Initialize a dummy git repo
    subprocess.run(["git", "init", repo_dir], capture_output=True)
    subprocess.run(["git", "-C", repo_dir, "remote", "add", "origin", "https://github.com/example/mockrepo.git"], capture_output=True)

    return repo_dir

async def benchmark():
    # Disable rate limiter for benchmarking
    limiter.enabled = False

    repo_dir = setup_mock_repo()

    # mock aegis command
    bin_dir = tempfile.mkdtemp()
    aegis_mock = os.path.join(bin_dir, "aegis")
    with open(aegis_mock, "w") as f:
        # sleep 0.1 to simulate real work and show blocking vs non-blocking difference clearly
        f.write("#!/bin/bash\nsleep 0.1\necho '{\"findings\": []}'\n")
    os.chmod(aegis_mock, 0o700)

    git_mock = os.path.join(bin_dir, "git")
    with open(git_mock, "w") as f:
        # sleep 0.1 to simulate git work
        f.write("#!/bin/bash\nsleep 0.1\necho 'https://github.com/example/mockrepo.git'\n")
    os.chmod(git_mock, 0o700)

    os.environ["PATH"] = bin_dir + ":" + os.environ.get("PATH", "")

    N = 20

    print(f"Benchmarking repo_intake with {N} concurrent requests...")

    async def make_request():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            start = time.time()
            resp = await ac.post("/repo/intake", json={"path": repo_dir}, headers={"X-AEGIS-Key": AEGIS_API_KEY})
            end = time.time()
            return end - start, resp.status_code

    start_total = time.time()
    tasks = [make_request() for _ in range(N)]
    results = await asyncio.gather(*tasks)
    end_total = time.time()

    total_time = end_total - start_total

    success = sum(1 for _, code in results if code == 200)
    failed = sum(1 for _, code in results if code != 200)

    print(f"Total time for {N} requests: {total_time:.4f}s")
    print(f"Success: {success}, Failed: {failed}")

if __name__ == "__main__":
    asyncio.run(benchmark())
