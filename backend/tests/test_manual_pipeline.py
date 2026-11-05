import asyncio
import threading

import httpx
from sqlmodel import Session, SQLModel, create_engine

import app.main as main
from app.database import get_session
from app.devsecops import service


async def run_in_test_thread(fn, *args, **kwargs):
    # This environment's Python 3.14 default executor hangs during loop shutdown.
    loop = asyncio.get_running_loop()
    result = loop.create_future()

    def work():
        try:
            value = fn(*args, **kwargs)
            loop.call_soon_threadsafe(result.set_result, value)
        except Exception as error:
            loop.call_soon_threadsafe(result.set_exception, error)

    threading.Thread(target=work, daemon=True).start()
    return await result


def test_manual_pipeline_runs_in_background_and_records_real_metadata(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'pipeline.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main.asyncio, "to_thread", run_in_test_thread)
    monkeypatch.setattr(main, "engine", engine)
    monkeypatch.setattr(service, "engine", engine)
    main._manual_pipeline_status.update(status="idle", run_id=None, error=None)
    with Session(engine) as session:
        token = asyncio.run(main.register(main.RegisterRequest(name="Analyst", email="analyst@example.test", password="password"), session))["token"]

    monkeypatch.setattr(service, "run_real_sast_scan", lambda: {"status": "PASSED", "engine": "Bandit", "loc_scanned": 42})
    monkeypatch.setattr(service, "run_dependency_scan", lambda: {"status": "NOT RUN", "engine": "pip-audit", "reason": "Scanner is not installed"})
    monkeypatch.setattr(service, "run_optional_scan", lambda executable, *args: {"status": "NOT RUN", "engine": executable, "reason": "Scanner is not installed"})
    started, release = threading.Event(), threading.Event()
    original = service.trigger_pipeline_scan

    def delayed_scan(**kwargs):
        started.set()
        if not release.wait(5):
            raise RuntimeError("Test timed out")
        return original(**kwargs)

    monkeypatch.setattr(main, "trigger_pipeline_scan", delayed_scan)

    async def get_test_session():
        with Session(engine) as session:
            yield session

    main.app.dependency_overrides[get_session] = get_test_session

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test") as client:
            assert (await client.post("/api/devsecops/runs/manual")).status_code == 401
            headers = {"Authorization": f"Bearer {token}"}
            response = await client.post("/api/devsecops/runs/manual", headers=headers)
            assert response.status_code == 202 and response.json()["status"] == "running"
            for _ in range(200):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            assert (await client.get("/api/devsecops/runs/manual/status", headers=headers)).json()["status"] == "running"
            assert (await client.post("/api/devsecops/runs/manual", headers=headers)).status_code == 409
            release.set()
            for _ in range(300):
                status = (await client.get("/api/devsecops/runs/manual/status", headers=headers)).json()
                if status["status"] != "running":
                    break
                await asyncio.sleep(0.01)
            assert status["status"] == "complete"
            runs = (await client.get("/api/devsecops/runs", headers=headers)).json()["runs"]
            assert len(runs) == 1 and runs[0]["id"] == status["run_id"]
            assert runs[0]["developer"] == "analyst@example.test"
            assert runs[0]["branch"] == "Not specified" and runs[0]["commit_sha"] == "Not available"
            assert runs[0]["status"] == "INCOMPLETE"
            assert runs[0]["details"]["sast"]["loc_scanned"] == 42
            assert runs[0]["details"]["dependencies"]["reason"] == "Scanner is not installed"

    try:
        asyncio.run(asyncio.wait_for(exercise(), timeout=10))
    finally:
        release.set()
        main.app.dependency_overrides.clear()
        main._manual_pipeline_status.update(status="idle", run_id=None, error=None)
        engine.dispose()


def test_manual_pipeline_failure_is_visible(monkeypatch):
    monkeypatch.setattr(main.asyncio, "to_thread", run_in_test_thread)
    def fail(**kwargs):
        raise RuntimeError("private scanner details")
    monkeypatch.setattr(main, "trigger_pipeline_scan", fail)
    main._manual_pipeline_status.update(status="running", run_id=None, error=None)
    try:
        asyncio.run(main._run_manual_pipeline_checks("analyst@example.test"))
        assert main._manual_pipeline_status["status"] == "failed"
        assert "could not be completed" in main._manual_pipeline_status["error"]
        assert "private scanner details" not in main._manual_pipeline_status["error"]
    finally:
        main._manual_pipeline_status.update(status="idle", run_id=None, error=None)
