"""Entrenamiento comparativo (Línea Base + 4 Modelos), 5-Fold CV, validación LODO y registro SHA-256."""

import os
import sys
import json
import time
import hashlib
import joblib
import numpy as np
import pandas as pd
from scipy.stats import wilcoxon
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from src.data.preprocess import (
    load_device_data,
    load_single_device_splits,
    DEVICE_NAMES,
    META_COLS,
)


def compute_sha256(filepath: str) -> str:
    """Calcula el hash criptográfico SHA-256 de un artefacto serializado."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def evaluate_classifier(
    model, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray, X_test: np.ndarray, y_test: np.ndarray, run_cv: bool = True
) -> dict:
    """Evalúa un clasificador con 5-Fold CV en Train, métricas en Val y métricas finales en Test."""
    if run_cv:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_f1 = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
        cv_mean = round(float(np.mean(cv_f1)), 4)
        cv_std = round(float(np.std(cv_f1)), 4)
    else:
        cv_mean, cv_std = 0.0, 0.0

    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    t_train = time.perf_counter() - t0

    # Para inferencia online paquete a paquete (batch_size=1), n_jobs=1 evita el overhead
    # de sincronización de hilos de joblib (~25 ms), reduciendo la latencia a ~1 ms.
    if hasattr(model, "n_jobs"):
        model.n_jobs = 1

    # Evaluación en conjunto de Validación (15%)
    val_pred = model.predict(X_val)
    val_f1 = round(float(f1_score(y_val, val_pred, zero_division=0)), 4)

    # Evaluación en conjunto de Prueba independiente (15%)
    t_inf0 = time.perf_counter()
    y_pred = model.predict(X_test)
    t_inf_batch = time.perf_counter() - t_inf0
    batch_ms_per_sample = (t_inf_batch / len(X_test)) * 1000.0

    # Medición de latencia unitaria real (1 paquete a la vez, promedio sobre 100 muestras)
    single_times = []
    for i in range(min(100, len(X_test))):
        sample_1d = X_test[i : i + 1]
        ts0 = time.perf_counter()
        _ = model.predict(sample_1d)
        single_times.append((time.perf_counter() - ts0) * 1000.0)
    single_sample_ms = float(np.mean(single_times))

    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
    else:
        y_prob = y_pred.astype(float)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    try:
        roc_auc = round(float(roc_auc_score(y_test, y_prob)), 4)
        pr_auc = round(float(average_precision_score(y_test, y_prob)), 4)
    except ValueError:
        roc_auc, pr_auc = 0.5, 0.5

    return {
        "cv_f1_mean": cv_mean,
        "cv_f1_std": cv_std,
        "val_f1": val_f1,
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "train_time_sec": round(t_train, 3),
        "inference_ms_batch_per_sample": round(batch_ms_per_sample, 5),
        "inference_ms_single_packet": round(single_sample_ms, 4),
    }


def run_lodo_validation(sample_per_device: int = 6000) -> dict:
    """Ejecuta la validación Leave-One-Device-Out (LODO) sobre los 9 dispositivos IoT."""
    print("\n" + "=" * 70)
    print("EJECUTANDO VALIDACIÓN LEAVE-ONE-DEVICE-OUT (LODO) — 9 DISPOSITIVOS")
    print("=" * 70)

    device_frames = {}
    for dev_id in range(1, 10):
        tr, va, te = load_single_device_splits(
            device_id=dev_id,
            sample_benign=sample_per_device // 2,
            sample_attack=sample_per_device // 2,
            stabilize_jitter=True,
        )
        device_frames[dev_id] = pd.concat([tr, va, te], ignore_index=True)

    feature_cols = [c for c in device_frames[1].columns if c not in META_COLS]
    folds = {}
    lr_f1_list, dt_f1_list, rf_f1_list, gb_f1_list, svm_f1_list = [], [], [], [], []
    lr_fpr_list, rf_fpr_list, gb_fpr_list = [], [], []

    for held_out in range(1, 10):
        train_df = pd.concat(
            [df for d, df in device_frames.items() if d != held_out], ignore_index=True
        )
        test_df = device_frames[held_out]

        scaler = StandardScaler()
        X_tr = scaler.fit_transform(train_df[feature_cols])
        y_tr = train_df["target"].to_numpy()
        X_te = scaler.transform(test_df[feature_cols])
        y_te = test_df["target"].to_numpy()

        models_lodo = {
            "lr": LogisticRegression(max_iter=1000, random_state=42),
            "dt": DecisionTreeClassifier(max_depth=8, random_state=42),
            "rf": RandomForestClassifier(
                n_estimators=100, max_depth=12, max_features="sqrt", random_state=42, n_jobs=-1
            ),
            "gb": HistGradientBoostingClassifier(max_depth=8, random_state=42),
            "svm": LinearSVC(max_iter=2000, random_state=42),
        }

        fold_metrics = {"device_id": held_out, "device_name": DEVICE_NAMES[held_out]}
        for m_key, clf in models_lodo.items():
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_te)
            tn, fp, fn, tp = confusion_matrix(y_te, preds).ravel()
            f1_val = round(float(f1_score(y_te, preds, zero_division=0)), 4)
            prec_val = round(float(precision_score(y_te, preds, zero_division=0)), 4)
            rec_val = round(float(recall_score(y_te, preds, zero_division=0)), 4)
            fpr_val = round(float(fp / (fp + tn)), 4)

            fold_metrics[m_key] = {
                "f1": f1_val,
                "precision": prec_val,
                "recall": rec_val,
                "fpr": fpr_val,
            }

        lr_f1_list.append(fold_metrics["lr"]["f1"])
        dt_f1_list.append(fold_metrics["dt"]["f1"])
        rf_f1_list.append(fold_metrics["rf"]["f1"])
        gb_f1_list.append(fold_metrics["gb"]["f1"])
        svm_f1_list.append(fold_metrics["svm"]["f1"])

        lr_fpr_list.append(fold_metrics["lr"]["fpr"])
        rf_fpr_list.append(fold_metrics["rf"]["fpr"])
        gb_fpr_list.append(fold_metrics["gb"]["fpr"])

        folds[f"device_{held_out}"] = fold_metrics
        print(
            f"  [Fold Disp. {held_out}: {DEVICE_NAMES[held_out]:<33}] "
            f"LR F1={fold_metrics['lr']['f1']:.4f} (FPR={fold_metrics['lr']['fpr']*100:5.2f}%) | "
            f"RF F1={fold_metrics['rf']['f1']:.4f} (FPR={fold_metrics['rf']['fpr']*100:5.2f}%) | "
            f"GB F1={fold_metrics['gb']['f1']:.4f}"
        )

    # Prueba estadística no paramétrica de Wilcoxon (RF vs LR y GB vs LR)
    try:
        _, p_val_rf_lr = wilcoxon(rf_f1_list, lr_f1_list, zero_method="zsplit")
    except Exception:
        p_val_rf_lr = 1.0

    summary = {
        "lr_f1_mean": round(float(np.mean(lr_f1_list)), 4),
        "lr_f1_std": round(float(np.std(lr_f1_list)), 4),
        "lr_fpr_mean": round(float(np.mean(lr_fpr_list)), 4),
        "dt_f1_mean": round(float(np.mean(dt_f1_list)), 4),
        "dt_f1_std": round(float(np.std(dt_f1_list)), 4),
        "rf_f1_mean": round(float(np.mean(rf_f1_list)), 4),
        "rf_f1_std": round(float(np.std(rf_f1_list)), 4),
        "rf_fpr_mean": round(float(np.mean(rf_fpr_list)), 4),
        "gb_f1_mean": round(float(np.mean(gb_f1_list)), 4),
        "gb_f1_std": round(float(np.std(gb_f1_list)), 4),
        "gb_fpr_mean": round(float(np.mean(gb_fpr_list)), 4),
        "svm_f1_mean": round(float(np.mean(svm_f1_list)), 4),
        "svm_f1_std": round(float(np.std(svm_f1_list)), 4),
        "wilcoxon_p_value_rf_vs_lr": round(float(p_val_rf_lr), 5),
        "folds": folds,
    }
    print("-" * 70)
    print(
        f"[LODO RESUMEN 9 DISP] "
        f"LR F1={summary['lr_f1_mean']:.4f}±{summary['lr_f1_std']:.4f} (FPR={summary['lr_fpr_mean']*100:.2f}%) | "
        f"RF F1={summary['rf_f1_mean']:.4f}±{summary['rf_f1_std']:.4f} (FPR={summary['rf_fpr_mean']*100:.2f}%) | "
        f"GB F1={summary['gb_f1_mean']:.4f}±{summary['gb_f1_std']:.4f} (FPR={summary['gb_fpr_mean']*100:.2f}%)"
    )
    return summary


def train_and_evaluate_real():
    print("=" * 70)
    print("ENTRENAMIENTO ESTÁNDAR (70/15/15 TEMPORAL + 5-FOLD CV) Y LODO (9 DISP)")
    print("=" * 70)

    (
        X_train,
        X_val,
        X_test,
        y_train,
        y_val,
        y_test,
        scaler,
        feature_cols,
    ) = load_device_data(
        sample_benign=20000,
        sample_attack=20000,
        stabilize_jitter=True,
        return_val=True,
    )

    classifiers = {
        "dummy_majority": (DummyClassifier(strategy="most_frequent"), False),
        "baseline_logistic_regression": (
            LogisticRegression(max_iter=1000, random_state=42),
            True,
        ),
        "decision_tree": (DecisionTreeClassifier(max_depth=8, random_state=42), True),
        "random_forest": (
            RandomForestClassifier(
                n_estimators=100,
                max_depth=12,
                max_features="sqrt",
                random_state=42,
                n_jobs=-1,
            ),
            True,
        ),
        "gradient_boosting": (
            HistGradientBoostingClassifier(max_depth=8, random_state=42),
            True,
        ),
        "svm_calibrated": (
            CalibratedClassifierCV(LinearSVC(max_iter=2000, random_state=42), cv=3),
            True,
        ),
    }

    model_results = {}
    trained_objects = {}
    for name, (clf, do_cv) in classifiers.items():
        print(f"\n[MODEL] Entrenando y evaluando: {name}...")
        res = evaluate_classifier(
            clf, X_train, y_train, X_val, y_val, X_test, y_test, run_cv=do_cv
        )
        model_results[name] = res
        trained_objects[name] = clf
        print(
            f"  -> CV F1: {res['cv_f1_mean']:.4f}±{res['cv_f1_std']:.4f} | "
            f"Test F1: {res['f1_score']:.4f} | FPR: {res['fpr']*100:.2f}% | "
            f"Single-Packet Latency: {res['inference_ms_single_packet']:.3f} ms"
        )

    # Extraer Top 15 Feature Importances del modelo Random Forest
    rf_clf = trained_objects["random_forest"]
    rf_imp = pd.Series(rf_clf.feature_importances_, index=feature_cols).sort_values(
        ascending=False
    )
    top_15_rf = {k: round(float(v), 5) for k, v in rf_imp.head(15).items()}

    # Ejecutar experimento LODO sobre los 9 dispositivos
    lodo_summary = run_lodo_validation(sample_per_device=6000)

    registry_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "models_registry")
    )
    os.makedirs(registry_dir, exist_ok=True)

    artifacts_to_save = {
        "scaler_nbaiot.pkl": scaler,
        "model_baseline_lr.pkl": trained_objects["baseline_logistic_regression"],
        "model_candidate_dt.pkl": trained_objects["decision_tree"],
        "model_random_forest.pkl": trained_objects["random_forest"],
        "model_gradient_boosting.pkl": trained_objects["gradient_boosting"],
        "model_svm.pkl": trained_objects["svm_calibrated"],
    }

    sha256_manifest = {}
    for filename, obj in artifacts_to_save.items():
        fpath = os.path.join(registry_dir, filename)
        joblib.dump(obj, fpath)
        sha256_manifest[filename] = compute_sha256(fpath)

    with open(
        os.path.join(registry_dir, "artifacts_sha256.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(sha256_manifest, f, indent=4)

    full_metrics = {
        "dataset": "N-BaIoT (9 Commercial IoT Devices, 10 Botnet Attack Subtypes)",
        "split_protocol": "Chronological 70% Train / 15% Val / 15% Test + 5-Fold Stratified CV",
        "train_samples": int(len(y_train)),
        "val_samples": int(len(y_val)),
        "test_samples": int(len(y_test)),
        "n_features": len(feature_cols),
        "baseline_logistic_regression": model_results["baseline_logistic_regression"],
        "decision_tree": model_results["decision_tree"],
        "random_forest": model_results["random_forest"],
        "gradient_boosting": model_results["gradient_boosting"],
        "svm_calibrated": model_results["svm_calibrated"],
        "dummy_majority": model_results["dummy_majority"],
        "top_15_features_rf": top_15_rf,
        "lodo_9_devices": lodo_summary,
    }

    with open(
        os.path.join(registry_dir, "baseline_metrics.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(full_metrics, f, indent=4, ensure_ascii=False)

    with open(
        os.path.join(registry_dir, "lodo_metrics.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(lodo_summary, f, indent=4, ensure_ascii=False)

    print("\n[OK] Todos los modelos (.pkl), métricas JSON y hashes SHA-256 exportados en models_registry/.")


if __name__ == "__main__":
    train_and_evaluate_real()
