from graph_intune_mcp import insights, store


def test_analyze_and_render():
    states = [store.normalize(s) for s in [
        {"id": "1", "deviceName": "a", "encryptionState": "encrypted", "encryptionReadinessState": "ready"},
        {"id": "2", "deviceName": "b", "encryptionState": "notEncrypted", "encryptionReadinessState": "notReady"},
        {"id": "3", "deviceName": "c", "encryptionState": "notEncrypted"}]]
    devices = [{"id": "2", "operatingSystem": "Windows", "lastSyncDateTime": store.now().isoformat()},
               {"id": "1", "operatingSystem": "Windows"}]
    r = insights.analyze(insights.enrich(states, devices))
    assert r["encrypted_pct"] == 33.3 and r["health_grade"] == "D"
    assert [d["device_name"] for d in r["at_risk_active_unencrypted"]] == ["b"]
    assert r["never_synced_count"] == 2
    assert "Encryption Health" in insights.render_html(r)
