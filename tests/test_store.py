from datetime import timedelta

from graph_intune_mcp import store


def dev(i, state):
    return {"id": str(i), "deviceName": f"pc{i}", "encryptionState": state}


def test_trend_and_changes():
    db = store.connect(":memory:")
    store.save_snapshot(db, [dev(1, "notEncrypted"), dev(2, "encrypted")], store.now() - timedelta(days=5))
    store.save_snapshot(db, [dev(1, "encrypted"), dev(2, "encrypted")])
    t = store.trend(db, 30)
    assert [p["encrypted_pct"] for p in t] == [50.0, 100.0]
    assert store.changes(db, 30) == [
        {"device_id": "1", "device_name": "pc1", "previous": "notEncrypted", "current": "encrypted"}]
    assert len(store.trend(db, 1)) == 1


def test_normalize_encryption_detail_fields():
    state = {
        **dev(1, "encrypted"),
        "advancedBitLockerStates": "success",
        "fileVaultStates": "success",
    }

    normalized = store.normalize(state)

    assert normalized["bitlocker_state"] == "success"
    assert normalized["filevault_state"] == "success"
