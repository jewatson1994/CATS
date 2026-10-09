"""Exercise real disk-backed scan preparation concurrently with Portal health."""
import asyncio
import json
import os
import time

import httpx
from test_scan_worker_coordination import database
from app import main


def test_disk_backed_preparation_keeps_portal_responsive(database, monkeypatch, tmp_path):
    monkeypatch.setattr(main, "SessionLocal", database)
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path / "jobs")
    size = int(os.getenv("CATS_SCAN_BENCHMARK_MIB", "8")) * 1024**2
    upload = tmp_path / "uploaded.tar"
    block = os.urandom(1024**2)
    with upload.open("wb") as stream:
        for _ in range(size // len(block)):
            stream.write(block)
    async def exercise():
        latencies = []
        start = time.perf_counter()
        with upload.open("rb") as stream:
            preparation = asyncio.create_task(main._prepare_public_scan("", image_archive=(stream, "uploaded.tar"), owner_user_id=17))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://portal") as client:
                while not preparation.done():
                    before = time.perf_counter()
                    response = await client.get("/health")
                    latencies.append(time.perf_counter() - before)
                    assert response.status_code == 200
                    await asyncio.sleep(0.01)
                job_id = await preparation
        elapsed = time.perf_counter() - start
        assert latencies and max(latencies) < 1.0
        job_root = main.PUBLIC_JOB_ROOT / job_id
        assert not (job_root / "input" / "image-archives").exists()
        assert (job_root / "input.tar.gz").stat().st_size >= size
        retained = sum(path.stat().st_size for path in job_root.rglob("*") if path.is_file())
        assert retained < size + 1024**2
        print(json.dumps({"upload_mib": size // 1024**2, "preparation_seconds": round(elapsed, 3),
                          "worst_health_seconds": round(max(latencies), 3), "health_requests": len(latencies),
                          "retained_mib": round(retained / 1024**2, 2)}))
    asyncio.run(exercise())
