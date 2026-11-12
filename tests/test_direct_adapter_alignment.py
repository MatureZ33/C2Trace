"""The direct baseline must expose its explicit entities to the trace scorer."""
import copy

from c2trace.baseline.llm_direct import prediction_to_casefile
from c2trace.baseline.prediction_ir import PredictionIR


def test_direct_adapter_preserves_prediction_and_action_arguments():
    prediction = PredictionIR(
        case_id="AURORA-CHAIN-001",
        observed_entities=[
            {"finding_type": "process", "value": "agent.exe", "details": {"pid": 7}},
            {"finding_type": "file", "value": r"C:\Public\agent.exe", "details": {}},
            {"finding_type": "file", "value": "reported-name", "details": {"path": r"C:\Other\file.bin"}},
            {"finding_type": "network_connection", "value": "192.0.2.1:443", "details": {"pid": 7}},
        ],
        proposed_actions=[{"tool": "kill_process", "arguments": {"pid": 7}}],
    )
    before = copy.deepcopy(prediction.to_dict())
    result = prediction_to_casefile(prediction)
    process, file, existing_path, network = result["findings"]
    assert process["finding_type"] == "process_detail"
    assert process["details"] == {"pid": 7}  # No path inferred from other findings.
    assert file["finding_type"] == "file_metadata"
    assert file["details"]["path"] == r"C:\Public\agent.exe"
    assert existing_path["details"]["path"] == r"C:\Other\file.bin"
    assert network["finding_type"] == "network_connection"
    assert result["proposed_actions"] == before["proposed_actions"]
    assert result["action_results"][0]["arguments"] == {"pid": 7}
    assert prediction.to_dict() == before
