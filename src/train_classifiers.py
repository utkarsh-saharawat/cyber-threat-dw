from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, average_precision_score,
                             confusion_matrix)
from xgboost import XGBClassifier
from src.dataset import load_dataset


def evaluate(name, model, X_test, y_test):
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print(f"\n=== {name} ===")
    print(classification_report(y_test, pred, digits=4,
                                target_names=["normal", "attack"]))
    print("PR-AUC:", round(average_precision_score(y_test, proba), 4))
    print("Confusion matrix [[TN FP], [FN TP]]:")
    print(confusion_matrix(y_test, pred))


def main():
    X, y, _ = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)
    print("Train:", X_train.shape, "| Test:", X_test.shape)

    print("\nTraining Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, class_weight="balanced_subsample",
                                n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train)
    evaluate("Random Forest", rf, X_test, y_test)

    print("\nTraining XGBoost...")
    ratio = (y_train == 0).sum() / (y_train == 1).sum()
    xgb = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                        scale_pos_weight=ratio, eval_metric="aucpr",
                        n_jobs=-1, random_state=42)
    xgb.fit(X_train, y_train)
    evaluate("XGBoost", xgb, X_test, y_test)


if __name__ == "__main__":
    main()
