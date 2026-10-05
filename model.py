import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Dataset load
data = pd.read_csv("phishing_dataset.csv")

# Features
X = data.drop("label", axis=1)

# Target
y = data["label"]

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# Training
model.fit(X_train, y_train)

# Accuracy
accuracy = model.score(X_test, y_test)

print("Model Accuracy:", accuracy)

# Save model
joblib.dump(model, "phishing_model.pkl")

print("Model saved successfully!")