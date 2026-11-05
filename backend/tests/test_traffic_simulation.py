import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.main as main
from app.models.core import Alert, ThreatEvent


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


@pytest.mark.parametrize("scenario_id,expected", [
    ("ssh_brute_force", "Brute Force"), ("web_login_brute_force", "Brute Force"),
    ("rdp_brute_force", "Brute Force"), ("port_scan", "Port Scan"),
    ("database_port_scan", "Port Scan"), ("http_flood", "DoS"),
    ("api_flood", "DoS"), ("dns_flood", "DoS"),
])
def test_scenarios_use_real_model_and_store_simulated_event(session, scenario_id, expected):
    request = main.SimulationRequest(scenario=scenario_id, target="test-service.example:443")
    result = asyncio.run(main.simulate_live_traffic_burst(session, request))
    assert result["analysis"]["prediction"] == expected
    assert result["target"] == "test-service.example:443" and result["logged"]
    event = session.exec(select(ThreatEvent)).one()
    assert event.simulated and event.destination == "test-service.example:443"
    assert "Simulated" in session.exec(select(Alert)).one().title
    assert asyncio.run(main.get_threats(session))[0]["simulated"] is True


def test_scenario_validation_defaults_and_model_error(session, monkeypatch):
    scenarios = asyncio.run(main.get_simulation_scenarios())["scenarios"]
    assert len(scenarios) == 8
    for request in [main.SimulationRequest(scenario="unknown"), main.SimulationRequest(scenario="http_flood", target="   "),
                    main.SimulationRequest(scenario="http_flood", target="bad\nlabel")]:
        with pytest.raises(HTTPException) as error:
            asyncio.run(main.simulate_live_traffic_burst(session, request))
        assert error.value.status_code == 400
    result = asyncio.run(main.simulate_live_traffic_burst(session, main.SimulationRequest(scenario="http_flood")))
    assert result["target"] == main.SIMULATION_SCENARIOS["http_flood"]["target"]
    monkeypatch.setattr(main, "analyze_event", lambda _: {"error": "Model unavailable"})
    with pytest.raises(HTTPException) as error:
        asyncio.run(main.simulate_live_traffic_burst(session, main.SimulationRequest(scenario="http_flood")))
    assert error.value.status_code == 503


def test_simulation_http_api_and_legacy_request(monkeypatch, tmp_path):
    import httpx
    from app.database import get_session

    engine = create_engine(f"sqlite:///{tmp_path / 'simulation.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main, "engine", engine)
    with Session(engine) as session:
        token = asyncio.run(main.register(main.RegisterRequest(name="Tester", email="tester@example.test", password="password"), session))["token"]

    async def get_test_session():
        with Session(engine) as session:
            yield session

    main.app.dependency_overrides[get_session] = get_test_session

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test", headers={"Authorization": f"Bearer {token}"}) as client:
            catalog = await client.get("/api/threats/simulation-scenarios")
            assert catalog.status_code == 200 and len(catalog.json()["scenarios"]) == 8
            response = await client.post("/api/threats/simulate", json={"scenario": "api_flood", "target": "api.internal:443"})
            assert response.status_code == 200 and response.json()["target"] == "api.internal:443"
            assert response.json()["analysis"]["prediction"] == "DoS"
            assert (await client.post("/api/threats/simulate", json={"scenario": "unknown"})).status_code == 400
            assert (await client.post("/api/threats/simulate")).status_code == 200

    try:
        asyncio.run(asyncio.wait_for(exercise(), timeout=10))
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()


def test_existing_threats_get_simulation_flag_on_startup(monkeypatch, tmp_path):
    from sqlalchemy import text
    from app import database

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE threatevent (id VARCHAR PRIMARY KEY, time DATETIME, type VARCHAR, source VARCHAR, severity VARCHAR, status VARCHAR)"))
        connection.execute(text("INSERT INTO threatevent (id, time, type, source, severity, status) VALUES ('old', '2026-01-01 00:00:00', 'DoS', '192.0.2.1', 'HIGH', 'Open')"))
    monkeypatch.setattr(database, "engine", engine)
    database.init_db()
    with Session(engine) as session:
        assert session.get(ThreatEvent, "old").simulated is False
    engine.dispose()
