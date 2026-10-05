from pathlib import Path
import joblib

MODEL = Path(__file__).parent / "model.joblib"

def ml_signal(event):
    if not MODEL.exists():
        return {"prediction": 0, "probability": 0.0, "top_features": []}

    model = joblib.load(MODEL)
    dangerous = {".exe",".msi",".bat",".cmd",".ps1",".vbs",".js",".jar",".dmg",".pkg",".sh",".command",".app",".scr",".hta"}
    features = [[
        int(event.get("event_type") == "usb_or_volume_inserted"),
        int(event.get("event_type") == "file_downloaded"),
        int((event.get("extension") or "").lower() in dangerous),
        int(event.get("event_type") == "process"),
        int(event.get("event_type") == "network")
    ]]
    prediction = int(model.predict(features)[0])
    probability = float(model.predict_proba(features)[0][1])
    names = ["usb", "download", "dangerous_file", "process", "network"]
    importances = getattr(model, "feature_importances_", [0] * 5)
    top = sorted(zip(names, importances), key=lambda x: x[1], reverse=True)[:3]
    return {
        "prediction": prediction,
        "probability": probability,
        "top_features": [f"{n}={v:.2f}" for n,v in top if v > 0]
    }
