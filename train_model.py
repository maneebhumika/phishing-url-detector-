import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from feature_extraction import extract_features

# Dataset
DATASET = "dataset.csv"

print("Loading dataset...")
data = pd.read_csv(DATASET)

print("Dataset loaded successfully!")
print("Columns:", data.columns.tolist())

# Find URL column
url_column = None
for col in data.columns:
    if col.lower() in ["url", "urls", "website", "link", "domain", "site", "full_url", "web_url"]:
        url_column = col
        break

if url_column is None:
    raise ValueError(f"URL column not found in dataset. Available columns: {list(data.columns)}")

# Find label column
label_column = None
for col in data.columns:
    if col.lower() in ["label", "labels", "class", "target", "status", "result"]:
        label_column = col
        break

if label_column is None:
    raise ValueError(f"Label column not found in dataset. Available columns: {list(data.columns)}")

print("URL column:", url_column)
print("Label column:", label_column)

# Extract features
print("Extracting URL features...")
features = data[url_column].astype(str).apply(extract_features)
X = pd.DataFrame(features.tolist())

# Label handling
y = data[label_column].astype(str).str.strip().str.lower()

label_map = {
    "phishing": 1,
    "phish": 1,
    "malicious": 1,
    "1": 1,
    "true": 1,
    "yes": 1,

    "legitimate": 0,
    "legit": 0,
    "benign": 0,
    "safe": 0,
    "0": 0,
    "false": 0,
    "no": 0
}

y = y.map(label_map)

if y.isna().any():
    unknown = sorted(y[y.isna()].unique().tolist())
    raise ValueError(f"Unknown values found in label column: {unknown}")

print("Features created successfully!")
print("Total samples:", len(X))

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Train model
print("Training Random Forest model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# Test model
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print("\nModel trained successfully!")
print("Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(y_test, predictions))

# Save model
joblib.dump(model, "phishing_model.pkl")

print("\nModel saved as phishing_model.pkl")
print("Training completed successfully!")