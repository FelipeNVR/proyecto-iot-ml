"""Entrenamiento de 3 Anillos de Defensa (Binario, Multiclase de Ataques y Zero-Day Novelty Detection) + LODO Adaptativo y Auditoría ML."""

import os
import sys
import json
import time
import hashlib
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
import sklearn
from scipy.stats import wilcoxon
from sklearn.base import clone
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier,
    HistGradientBoostingClassifier,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
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
    load_distant_horizon_data,
    DEVICE_NAMES,
    META_COLS,
)
from src.streaming.firewall_controller import (
    get_adaptive_threshold,
    HIGH_BANDWIDTH_CAMERA_DEVICES,
)


def compute_sha256(filepath: str) -> str:
    """Calcula el hash criptográfico SHA-256 de un artefacto serializado."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonicalize_attack_label(arr: np.ndarray) -> np.ndarray:
    """
    Agrupa BASHLITE_TCP y BASHLITE_UDP bajo la firma canónica BASHLITE_SPOOF_FLOOD
    cuando se evalúa a nivel de vectores AfterImage puros (sin cabecera L4 TCP/UDP),
    dado que ambos ataques falsifican la IP origen en cada paquete de 60 bytes (w=1, mean=60, var=0).
    """
    out = np.asarray(arr, dtype=object).copy()
    mask = (out == "BASHLITE_TCP") | (out == "BASHLITE_UDP")
    out[mask] = "BASHLITE_SPOOF_FLOOD"
    return out


def evaluate_classifier(
    model,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    scaler: StandardScaler = None,
    run_cv: bool = True,
) -> dict:
    """
    Evalúa un clasificador con:
    - 5-Fold CV Temporal sin fuga de escalado (Pipeline(StandardScaler, clf) y shuffle=False)
    - Métricas en Train, Val y Test (para auditar sobreajuste).
    """
    if run_cv:
        X_train_raw = (
            scaler.inverse_transform(X_train) if scaler is not None else X_train
        )
        cv_pipe = Pipeline([("fold_scaler", StandardScaler()), ("clf", clone(model))])
        cv = StratifiedKFold(n_splits=5, shuffle=False)
        cv_f1 = cross_val_score(
            cv_pipe, X_train_raw, y_train, cv=cv, scoring="f1", n_jobs=-1
        )
        cv_mean = round(float(np.mean(cv_f1)), 4)
        cv_std = round(float(np.std(cv_f1)), 4)
    else:
        cv_mean, cv_std = 0.0, 0.0

    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    t_train = time.perf_counter() - t0

    if hasattr(model, "n_jobs"):
        model.n_jobs = 1

    train_pred = model.predict(X_train)
    train_f1 = round(float(f1_score(y_train, train_pred, zero_division=0)), 4)

    val_pred = model.predict(X_val)
    val_f1 = round(float(f1_score(y_val, val_pred, zero_division=0)), 4)

    t_inf0 = time.perf_counter()
    y_pred = model.predict(X_test)
    t_inf_batch = time.perf_counter() - t_inf0
    batch_ms_per_sample = (t_inf_batch / len(X_test)) * 1000.0

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
        "train_f1": train_f1,
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


def apply_burst_consensus(preds: np.ndarray, window: int = 3) -> np.ndarray:
    """
    Filtro de Persistencia de Ráfaga (Temporal Consensus IPS):
    En dispositivos multimedia (cámaras IP), un pico aislado de 1 trama de video no debe
    disparar bloqueo si los paquetes adyacentes son normales. Se exige mayoría en ventana móvil
    de k=3 tramas secuenciales para confirmar ataque volumétrico sostenido.
    """
    if len(preds) < window:
        return preds
    s = pd.Series(preds).rolling(window=window, min_periods=1).mean().to_numpy()
    return (s >= 0.66).astype(int)


def run_lodo_validation(sample_per_device: int = 4000) -> dict:
    """Ejecuta la validación Leave-One-Device-Out (LODO) sobre los 9 dispositivos IoT,
    comparando umbral estándar (0.50) vs. IPS con Umbral Adaptativo + Consenso de Ráfaga."""
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
    lr_fpr_list, dt_fpr_list, rf_fpr_list, gb_fpr_list, svm_fpr_list = (
        [],
        [],
        [],
        [],
        [],
    )
    rf_adapt_f1_list, rf_adapt_fpr_list = [], []

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
            "lr": LogisticRegression(max_iter=1000, C=0.1, random_state=42),
            "dt": DecisionTreeClassifier(
                max_depth=5, min_samples_leaf=20, random_state=42
            ),
            "rf": RandomForestClassifier(
                n_estimators=100,
                max_depth=8,
                min_samples_leaf=10,
                max_features="sqrt",
                random_state=42,
                n_jobs=-1,
            ),
            "gb": HistGradientBoostingClassifier(
                max_iter=100, max_depth=6, min_samples_leaf=20, random_state=42
            ),
            "svm": CalibratedClassifierCV(
                LinearSVC(C=0.1, max_iter=2000, random_state=42), cv=3
            ),
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

        # Calibrar umbral de cámaras estrictamente sobre los 8 dispositivos de entrenamiento (sin tocar test_df)
        if held_out in HIGH_BANDWIDTH_CAMERA_DEVICES:
            cam_benign_mask = (train_df["target"].to_numpy() == 0) & (
                train_df["device_id"].isin(HIGH_BANDWIDTH_CAMERA_DEVICES).to_numpy()
            )
            cam_train_probs = models_lodo["rf"].predict_proba(X_tr[cam_benign_mask])[:, 1]
            thr = round(
                float(np.clip(np.percentile(cam_train_probs, 99.5), 0.68, 0.76)), 2
            )
        else:
            thr = 0.50

        rf_probs = models_lodo["rf"].predict_proba(X_te)[:, 1]
        raw_adapt_preds = (rf_probs >= thr).astype(int)
        # Aplicar consenso de ráfaga (k=3) dentro de cada flujo/captura secuencial (source_csv)
        adapt_preds = np.zeros_like(raw_adapt_preds)
        src_arr = test_df["source_csv"].to_numpy()
        for scsv in np.unique(src_arr):
            mask_s = src_arr == scsv
            adapt_preds[mask_s] = apply_burst_consensus(
                raw_adapt_preds[mask_s], window=3
            )
        tn_a, fp_a, fn_a, tp_a = confusion_matrix(y_te, adapt_preds).ravel()
        fold_metrics["rf_adaptive"] = {
            "threshold": thr,
            "f1": round(float(f1_score(y_te, adapt_preds, zero_division=0)), 4),
            "precision": round(
                float(precision_score(y_te, adapt_preds, zero_division=0)), 4
            ),
            "recall": round(float(recall_score(y_te, adapt_preds, zero_division=0)), 4),
            "fpr": round(float(fp_a / (fp_a + tn_a)), 4),
        }

        lr_f1_list.append(fold_metrics["lr"]["f1"])
        dt_f1_list.append(fold_metrics["dt"]["f1"])
        rf_f1_list.append(fold_metrics["rf"]["f1"])
        gb_f1_list.append(fold_metrics["gb"]["f1"])
        svm_f1_list.append(fold_metrics["svm"]["f1"])
        rf_adapt_f1_list.append(fold_metrics["rf_adaptive"]["f1"])

        lr_fpr_list.append(fold_metrics["lr"]["fpr"])
        dt_fpr_list.append(fold_metrics["dt"]["fpr"])
        rf_fpr_list.append(fold_metrics["rf"]["fpr"])
        gb_fpr_list.append(fold_metrics["gb"]["fpr"])
        svm_fpr_list.append(fold_metrics["svm"]["fpr"])
        rf_adapt_fpr_list.append(fold_metrics["rf_adaptive"]["fpr"])

        folds[f"device_{held_out}"] = fold_metrics
        print(
            f"  [Fold Disp. {held_out}: {DEVICE_NAMES[held_out]:<33}] "
            f"LR F1={fold_metrics['lr']['f1']:.4f} | "
            f"RF F1={fold_metrics['rf']['f1']:.4f} (FPR={fold_metrics['rf']['fpr']*100:5.2f}%) -> "
            f"RF+Adapt F1={fold_metrics['rf_adaptive']['f1']:.4f} (FPR={fold_metrics['rf_adaptive']['fpr']*100:5.2f}%)"
        )

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
        "dt_fpr_mean": round(float(np.mean(dt_fpr_list)), 4),
        "rf_f1_mean": round(float(np.mean(rf_f1_list)), 4),
        "rf_f1_std": round(float(np.std(rf_f1_list)), 4),
        "rf_fpr_mean": round(float(np.mean(rf_fpr_list)), 4),
        "rf_adaptive_f1_mean": round(float(np.mean(rf_adapt_f1_list)), 4),
        "rf_adaptive_f1_std": round(float(np.std(rf_adapt_f1_list)), 4),
        "rf_adaptive_fpr_mean": round(float(np.mean(rf_adapt_fpr_list)), 4),
        "gb_f1_mean": round(float(np.mean(gb_f1_list)), 4),
        "gb_f1_std": round(float(np.std(gb_f1_list)), 4),
        "gb_fpr_mean": round(float(np.mean(gb_fpr_list)), 4),
        "svm_f1_mean": round(float(np.mean(svm_f1_list)), 4),
        "svm_f1_std": round(float(np.std(svm_f1_list)), 4),
        "svm_fpr_mean": round(float(np.mean(svm_fpr_list)), 4),
        "wilcoxon_p_value_rf_vs_lr": round(float(p_val_rf_lr), 5),
        "folds": folds,
    }
    print("-" * 70)
    print(
        f"[LODO RESUMEN 9 DISP] "
        f"LR F1={summary['lr_f1_mean']:.4f} (FPR={summary['lr_fpr_mean']*100:.2f}%) | "
        f"RF Estándar F1={summary['rf_f1_mean']:.4f} (FPR={summary['rf_fpr_mean']*100:.2f}%) | "
        f"RF + Umbral Adaptativo IPS F1={summary['rf_adaptive_f1_mean']:.4f} (FPR={summary['rf_adaptive_fpr_mean']*100:.2f}%)"
    )
    return summary


def train_and_evaluate_real():
    t_pipeline_start = time.perf_counter()
    print("=" * 70)
    print("ENTRENAMIENTO DE 3 ANILLOS (BINARIO + MULTICLASE 10 ATAQUES + ZERO-DAY)")
    print("=" * 70)

    (
        X_train,
        X_val,
        X_test,
        y_train,
        y_val,
        y_test,
        atk_train,
        atk_test,
        scaler,
        feature_cols,
    ) = load_device_data(
        device_id=None,
        sample_benign=2500,
        sample_attack=2500,
        stabilize_jitter=True,
        return_val=True,
        return_attack_types=True,
    )

    classifiers = {
        "dummy_majority": (DummyClassifier(strategy="most_frequent"), False),
        "baseline_logistic_regression": (
            LogisticRegression(max_iter=1000, C=0.1, random_state=42),
            True,
        ),
        "decision_tree": (
            DecisionTreeClassifier(max_depth=5, min_samples_leaf=20, random_state=42),
            True,
        ),
        "random_forest": (
            RandomForestClassifier(
                n_estimators=100,
                max_depth=8,
                min_samples_leaf=10,
                max_features="sqrt",
                random_state=42,
                n_jobs=-1,
            ),
            True,
        ),
        "gradient_boosting": (
            HistGradientBoostingClassifier(
                max_iter=100, max_depth=6, min_samples_leaf=20, random_state=42
            ),
            True,
        ),
        "svm_calibrated": (
            CalibratedClassifierCV(
                LinearSVC(C=0.1, max_iter=2000, random_state=42), cv=3
            ),
            True,
        ),
    }

    model_results = {}
    trained_objects = {}
    for name, (clf, do_cv) in classifiers.items():
        print(f"\n[ANILLO 1 - BINARIO] Entrenando y evaluando: {name}...")
        res = evaluate_classifier(
            clf,
            X_train,
            y_train,
            X_val,
            y_val,
            X_test,
            y_test,
            scaler=scaler,
            run_cv=do_cv,
        )
        model_results[name] = res
        trained_objects[name] = clf
        print(
            f"  -> CV F1: {res['cv_f1_mean']:.4f}±{res['cv_f1_std']:.4f} | "
            f"Train F1: {res['train_f1']:.4f} | Val F1: {res['val_f1']:.4f} | "
            f"Test F1: {res['f1_score']:.4f} | FPR: {res['fpr']*100:.2f}% | "
            f"Latency: {res['inference_ms_single_packet']:.3f} ms"
        )

    # ----------------- ANILLO 2: CLASIFICADOR MULTICLASE DE ATAQUES -----------------
    print("\n[ANILLO 2 - MULTICLASE] Entrenando clasificador balanceado de firma de ataque...")
    mask_atk_tr = y_train == 1
    mask_atk_te = y_test == 1
    X_atk_tr, y_atk_tr = X_train[mask_atk_tr], atk_train[mask_atk_tr]
    X_atk_te, y_atk_te = X_test[mask_atk_te], atk_test[mask_atk_te]

    multiclass_rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_leaf=5,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    t_mc0 = time.perf_counter()
    multiclass_rf.fit(X_atk_tr, y_atk_tr)
    t_mc_train = round(time.perf_counter() - t_mc0, 3)
    multiclass_rf.n_jobs = 1

    mc_preds = multiclass_rf.predict(X_atk_te)
    mc_acc_raw = round(float(accuracy_score(y_atk_te, mc_preds)), 4)
    mc_f1_macro_raw = round(
        float(f1_score(y_atk_te, mc_preds, average="macro", zero_division=0)), 4
    )

    # Métricas sobre las 9 firmas estadísticas canónicas (agrupando BASHLITE_TCP/UDP Spoofed 60B)
    y_atk_te_canon = _canonicalize_attack_label(y_atk_te)
    mc_preds_canon = _canonicalize_attack_label(mc_preds)
    mc_acc = round(float(accuracy_score(y_atk_te_canon, mc_preds_canon)), 4)
    mc_f1_macro = round(
        float(
            f1_score(y_atk_te_canon, mc_preds_canon, average="macro", zero_division=0)
        ),
        4,
    )
    mc_f1_weighted = round(
        float(
            f1_score(
                y_atk_te_canon, mc_preds_canon, average="weighted", zero_division=0
            )
        ),
        4,
    )
    print(
        f"  -> Multiclase Firmas Canónicas (9 familias) Accuracy: {mc_acc:.4f} | "
        f"F1-Macro: {mc_f1_macro:.4f} (10-clases crudas Acc={mc_acc_raw:.4f})"
    )

    # ----------------- ANILLO 3: DETECTOR NO SUPERVISADO ZERO-DAY (NOVELTY DETECTION) -----------------
    print("\n[ANILLO 3 - ZERO-DAY] Entrenando LocalOutlierFactor (Novelty) exclusivamente con tráfico 100% Benigno...")
    X_benign_tr = X_train[y_train == 0]
    zeroday_iforest = Pipeline(
        [
            ("benign_scaler", StandardScaler()),
            (
                "novelty_detector",
                LocalOutlierFactor(
                    n_neighbors=15, contamination=0.03, novelty=True
                ),
            ),
        ]
    )
    t_zd0 = time.perf_counter()
    zeroday_iforest.fit(X_benign_tr)
    t_zd_train = round(time.perf_counter() - t_zd0, 3)

    # En Novelty Detection: -1 = Anomalía (Ataque / Zero-Day), +1 = Inlier (Benigno)
    zd_raw_preds = zeroday_iforest.predict(X_test)
    zd_binary_preds = (zd_raw_preds == -1).astype(int)
    tn_z, fp_z, fn_z, tp_z = confusion_matrix(y_test, zd_binary_preds).ravel()
    zd_recall_attacks = round(float(tp_z / (tp_z + fn_z)), 4)
    zd_fpr_benign = round(float(fp_z / (fp_z + tn_z)), 4)
    zd_f1 = round(float(f1_score(y_test, zd_binary_preds, zero_division=0)), 4)
    print(
        f"  -> Zero-Day Detector (Sin ver ataques en entrenamiento): "
        f"Tasa Detección Ataques={zd_recall_attacks*100:.2f}% | FPR={zd_fpr_benign*100:.2f}% | F1={zd_f1:.4f}"
    )

    # ----------------- VERIFICACIÓN EMPÍRICA DE AUDITORÍA ML -----------------
    print("\n[AUDITORÍA ML] Ejecutando pruebas de sanidad (Y-Randomization, Multi-Seed y Horizonte Distante)...")
    rng = np.random.RandomState(42)
    y_shuffled = rng.permutation(y_train)
    rf_sanity = RandomForestClassifier(
        n_estimators=50, max_depth=8, min_samples_leaf=10, random_state=42, n_jobs=-1
    )
    rf_sanity.fit(X_train, y_shuffled)
    sanity_preds = rf_sanity.predict(X_test)
    sanity_f1 = round(float(f1_score(y_test, sanity_preds, zero_division=0)), 4)
    sanity_acc = round(float(accuracy_score(y_test, sanity_preds)), 4)

    seed_f1s = []
    for s in [7, 42, 99, 123, 2026]:
        rf_s = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_leaf=10,
            max_features="sqrt",
            random_state=s,
            n_jobs=-1,
        )
        rf_s.fit(X_train, y_train)
        seed_f1s.append(round(float(f1_score(y_test, rf_s.predict(X_test))), 5))

    X_hor_df, y_hor = load_distant_horizon_data(skip_rows=10000)
    X_hor_scaled = scaler.transform(X_hor_df[feature_cols])
    rf_hor_preds = trained_objects["random_forest"].predict(X_hor_scaled)
    lr_hor_preds = trained_objects["baseline_logistic_regression"].predict(X_hor_scaled)
    tn_h, fp_h, fn_h, tp_h = confusion_matrix(y_hor, rf_hor_preds).ravel()
    hor_rf_f1 = round(float(f1_score(y_hor, rf_hor_preds)), 4)
    hor_rf_fpr = round(float(fp_h / (fp_h + tn_h)), 4)
    hor_lr_f1 = round(float(f1_score(y_hor, lr_hor_preds)), 4)
    print(
        f"  -> Y-Randomization F1={sanity_f1:.4f} | 5-Seed F1={np.mean(seed_f1s):.4f}±{np.std(seed_f1s):.4f} | "
        f"Horizonte Distante (+10k filas) RF F1={hor_rf_f1:.4f} (FPR={hor_rf_fpr*100:.2f}%)"
    )

    # Extraer Top 15 Feature Importances del modelo Random Forest Binario
    rf_clf = trained_objects["random_forest"]
    rf_imp = pd.Series(rf_clf.feature_importances_, index=feature_cols).sort_values(
        ascending=False
    )
    top_15_rf = {k: round(float(v), 5) for k, v in rf_imp.head(15).items()}

    # Ejecutar experimento LODO sobre los 9 dispositivos
    lodo_summary = run_lodo_validation(sample_per_device=4000)

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
        "model_multiclass_attack.pkl": multiclass_rf,
        "model_zeroday_iforest.pkl": zeroday_iforest,
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

    total_pipeline_sec = round(time.perf_counter() - t_pipeline_start, 2)
    trained_at_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    full_metrics = {
        "dataset": "N-BaIoT (9 Commercial IoT Devices, 10 Botnet Attack Subtypes)",
        "split_protocol": "Chronological 65% Train / 15% Val / 15% Test with 2.5% Temporal Purge Buffers + Leak-Free 5-Fold Pipeline CV",
        "training_audit": {
            "trained_at": trained_at_str,
            "pipeline_stage": "Fase Offline — Entrenamiento de 3 Anillos de Defensa (src/models/baseline.py)",
            "total_pipeline_duration_sec": total_pipeline_sec,
            "sklearn_version": sklearn.__version__,
            "devices_trained_count": 9,
            "devices_list": [f"{k}. {v}" for k, v in DEVICE_NAMES.items()],
            "defense_rings": [
                "Anillo 1 (Supervisado Binario): 5 clasificadores para detección rápida de tráfico malicioso.",
                "Anillo 2 (Clasificador Multiclase Balanceado): Identifica automáticamente la botnet (Mirai/BASHLITE) y su firma de ataque sin depender de etiquetas.",
                "Anillo 3 (No Supervisado Zero-Day): LocalOutlierFactor (Novelty Detection) entrenado solo con tráfico benigno para cazar intrusiones desconocidas.",
            ],
        },
        "ml_audit_verification": {
            "y_randomization_sanity_f1": sanity_f1,
            "y_randomization_sanity_acc": sanity_acc,
            "multi_seed_rf_f1_mean": round(float(np.mean(seed_f1s)), 5),
            "multi_seed_rf_f1_std": round(float(np.std(seed_f1s)), 5),
            "distant_horizon_10k_samples": int(len(y_hor)),
            "distant_horizon_rf_f1": hor_rf_f1,
            "distant_horizon_rf_fpr": hor_rf_fpr,
            "distant_horizon_lr_f1": hor_lr_f1,
        },
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
        "multiclass_attack_classifier": {
            "n_classes": len(multiclass_rf.classes_),
            "classes": [str(c) for c in multiclass_rf.classes_],
            "accuracy": mc_acc,
            "f1_macro": mc_f1_macro,
            "f1_weighted": mc_f1_weighted,
            "raw_10_classes_accuracy": mc_acc_raw,
            "raw_10_classes_f1_macro": mc_f1_macro_raw,
            "train_time_sec": t_mc_train,
        },
        "zeroday_isolation_forest": {
            "algorithm": "Pipeline(StandardScaler + LocalOutlierFactor(n_neighbors=15, contamination=0.03, novelty=True))",
            "trained_on": "100% Tráfico Benigno (No Supervisado)",
            "attack_detection_recall": zd_recall_attacks,
            "benign_fpr": zd_fpr_benign,
            "f1_score": zd_f1,
            "train_time_sec": t_zd_train,
        },
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

    print(
        f"\n[OK] Entrenamiento de 3 Anillos finalizado en {total_pipeline_sec}s ({trained_at_str}). "
        "8 artefactos (.pkl), métricas JSON y hashes SHA-256 actualizados."
    )


if __name__ == "__main__":
    train_and_evaluate_real()
