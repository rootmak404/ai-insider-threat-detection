from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier

X = [
 [0,0,0,1,0],[0,0,0,0,1],[0,1,0,0,0],[0,1,1,0,0],
 [1,0,0,0,0],[1,1,1,0,0],[0,1,1,1,0],[0,0,0,1,1],
 [1,0,0,1,0],[0,1,0,0,1]
]
y = [0,0,0,1,1,1,1,0,1,0]

model = RandomForestClassifier(
    n_estimators=40, max_depth=4, random_state=42, class_weight="balanced"
)
model.fit(X, y)
joblib.dump(model, Path(__file__).parent / "model.joblib")
print("model.joblib created")
