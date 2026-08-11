from analyzer.threat_detector import detect_threats


def test_detect_threats_returns_expected_fields_for_known_event():
    events = [
        {
            "event_id": "4625",
            "level": "Failure Audit",
            "time": "2024-01-01 00:00:00",
            "computer": "DC01",
            "provider": "Microsoft-Windows-Security",
        }
    ]

    threats = detect_threats(events)

    assert threats == [
        {
            "event_id": "4625",
            "threat": "Failed Login Attempt",
            "severity": "High",
            "level": "Failure Audit",
            "time": "2024-01-01 00:00:00",
            "computer": "DC01",
            "provider": "Microsoft-Windows-Security",
        }
    ]
