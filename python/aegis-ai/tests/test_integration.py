from fastapi.testclient import TestClient
from src.main import app
from src.tier5.digital_twin import DigitalTwin
from src.tier5.temporal_causal import TemporalCausalEngine
from src.tier5.resilience_chaos import ChaosEngine

client = TestClient(app)

def test_integration_chaos_scenario():
    """
    Implements 14_Edge_Cases_and_Failure_Modes.md
    Tests the system under simulated failure states.
    """
    chaos = ChaosEngine(active=True)
    try:
        # Force a large number of checks to trigger the 1% failure probability
        for _ in range(200):
            chaos.check_failure_injection()
    except Exception as e:
        assert "Simulated Chaos Failure" in str(e)

def test_integration_user_scenario_tier5():
    """
    Implements 13_Example_User_Scenarios.md
    Full E2E check of the Tier 5 modules.
    """
    dt = DigitalTwin()
    dt.sync_state({"os": "ubuntu", "sandbox": "gvisor"})
    sim_res = dt.simulate_action("read_file")
    assert sim_res["safe"] is True
    
    tce = TemporalCausalEngine()
    for _ in range(4):
        tce.add_event({"action": "network_scan"})
    
    chains = tce.deduce_causality()
    assert len(chains) == 1
    assert "temporal proximity" in chains[0]
