"""Módulo de ingesta, limpieza, estabilización de jitter y partición temporal sin data leakage."""

import os
import glob
from typing import Tuple, List, Dict, Optional
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

DEVICE_NAMES: Dict[int, str] = {
    1: "Danmini Doorbell",
    2: "Ecobee Thermostat",
    3: "Ennio Doorbell",
    4: "Philips B120N/10 Baby Monitor",
    5: "Provision PT-737E Security Camera",
    6: "Provision PT-838 Security Camera",
    7: "Samsung SNH 1011 Webcam",
    8: "SimpleHome XCS7-1002-WHT Camera",
    9: "SimpleHome XCS7-1003-WHT Camera",
}

META_COLS: List[str] = ["target", "attack_type", "device_id"]


def sanitize_jitter_features(df: pd.DataFrame) -> pd.DataFrame:
    """Mitiga el artefacto de inicialización por Unix Epoch Timestamp (~1.5e9 s)
    presente en las columnas HH_jit_* del extractor AfterImage (Kitsune) en N-BaIoT.
    Aplica estabilización logarítmica signada log1p(|x|) a las columnas HH_jit_*
    para comprimir el salto de 9 órdenes de magnitud sin perder monotonicidad."""
    out = df.copy()
    jit_cols = [c for c in out.columns if c.startswith("HH_jit_")]
    for col in jit_cols:
        vals = out[col].to_numpy(dtype=np.float64, copy=True)
        out[col] = np.sign(vals) * np.log1p(np.abs(vals))
    return out


def chronological_split(
    df: pd.DataFrame, train_frac: float = 0.70, val_frac: float = 0.15
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Divide un flujo secuencial en tres bloques temporales disjuntos:
    - Primer 70% cronológico -> Entrenamiento (Train)
    - Siguiente 15% cronológico -> Validación (Val)
    - Último 15% cronológico -> Prueba independiente (Test)
    Garantiza que no exista fuga temporal (Riesgo D3) entre muestras adyacentes."""
    n = len(df)
    i_train = int(n * train_frac)
    i_val = int(n * (train_frac + val_frac))
    return (
        df.iloc[:i_train].copy(),
        df.iloc[i_train:i_val].copy(),
        df.iloc[i_val:].copy(),
    )


def load_single_device_splits(
    data_dir: Optional[str] = None,
    device_id: int = 1,
    sample_benign: int = 20000,
    sample_attack: int = 20000,
    stabilize_jitter: bool = True,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Carga tráfico benigno y todos los subtipos de ataque disponibles (Mirai y BASHLITE)
    para un dispositivo específico, aplicando partición temporal 70/15/15 por cada captura."""
    if data_dir is None:
        data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))

    dev_name = DEVICE_NAMES.get(device_id, f"Device {device_id}")
    benign_path = os.path.join(data_dir, f"{device_id}.benign.csv")
    if not os.path.exists(benign_path):
        raise FileNotFoundError(f"No se encontró el archivo benigno: {benign_path}")

    # 1. Cargar tráfico benigno en orden cronológico y separar 70/15/15
    df_benign = pd.read_csv(benign_path, nrows=sample_benign).copy()
    if stabilize_jitter:
        df_benign = sanitize_jitter_features(df_benign)
    df_benign = df_benign.assign(
        target=0, attack_type="Benigno", device_id=device_id
    )
    b_train, b_val, b_test = chronological_split(df_benign)

    # 2. Descubrir dinámicamente todos los subtipos de ataque existentes para este dispositivo
    gafgyt_files = sorted(glob.glob(os.path.join(data_dir, f"{device_id}.gafgyt.*.csv")))
    mirai_files = sorted(glob.glob(os.path.join(data_dir, f"{device_id}.mirai.*.csv")))
    atk_paths = gafgyt_files + mirai_files
    if not atk_paths:
        raise FileNotFoundError(f"No se encontraron archivos de ataque para dispositivo {device_id}")

    rows_per_attack = max(100, sample_attack // len(atk_paths))
    train_parts, val_parts, test_parts = [b_train], [b_val], [b_test]

    for atk_path in atk_paths:
        parts = os.path.basename(atk_path).replace(".csv", "").split(".")
        botnet = "BASHLITE" if parts[1] == "gafgyt" else "Mirai"
        atk_label = f"{botnet}_{parts[2].upper()}"

        df_atk = pd.read_csv(atk_path, nrows=rows_per_attack).copy()
        if stabilize_jitter:
            df_atk = sanitize_jitter_features(df_atk)
        df_atk = df_atk.assign(
            target=1, attack_type=atk_label, device_id=device_id
        )
        a_tr, a_va, a_te = chronological_split(df_atk)
        train_parts.append(a_tr)
        val_parts.append(a_va)
        test_parts.append(a_te)

    df_train = pd.concat(train_parts, ignore_index=True)
    df_val = pd.concat(val_parts, ignore_index=True)
    df_test = pd.concat(test_parts, ignore_index=True)

    for split_df in (df_train, df_val, df_test):
        split_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        split_df.dropna(inplace=True)

    print(
        f"[DATA] Disp. {device_id} ({dev_name}): "
        f"Train={len(df_train)}, Val={len(df_val)}, Test={len(df_test)} "
        f"| Subtipos ataque={len(atk_paths)}"
    )
    return df_train, df_val, df_test


def load_device_data(
    data_dir: Optional[str] = None,
    device_id: int = 1,
    sample_benign: int = 20000,
    sample_attack: int = 20000,
    random_state: int = 42,
    stabilize_jitter: bool = True,
    return_val: bool = False,
):
    """Carga y escala sin data leakage los datos de un dispositivo (o retorna Train/Val/Test).
    Además exporta stream_sample_real.csv (500 muestras reales del conjunto Test) para el emulador."""
    if data_dir is None:
        data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))

    df_train, df_val, df_test = load_single_device_splits(
        data_dir=data_dir,
        device_id=device_id,
        sample_benign=sample_benign,
        sample_attack=sample_attack,
        stabilize_jitter=stabilize_jitter,
    )

    feature_cols: List[str] = [c for c in df_train.columns if c not in META_COLS]

    # Mezclar filas únicamente dentro de cada partición temporal ya separada
    df_train = df_train.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    df_val = df_val.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    df_test = df_test.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    # Exportar muestra equilibrada (250 benignas + 250 maliciosas) del conjunto TEST para streaming
    stream_sample = pd.concat(
        [
            df_test[df_test["target"] == 0].head(250),
            df_test[df_test["target"] == 1].head(250),
        ],
        ignore_index=True,
    )
    stream_path = os.path.join(data_dir, "stream_sample_real.csv")
    stream_sample.to_csv(stream_path, index=False)
    print(f"[DATA] Muestra de prueba para streaming exportada en: {stream_path} ({len(stream_sample)} filas)")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(df_train[feature_cols])
    X_val_scaled = scaler.transform(df_val[feature_cols])
    X_test_scaled = scaler.transform(df_test[feature_cols])

    if return_val:
        return (
            X_train_scaled,
            X_val_scaled,
            X_test_scaled,
            df_train["target"].to_numpy(),
            df_val["target"].to_numpy(),
            df_test["target"].to_numpy(),
            scaler,
            feature_cols,
        )

    return (
        X_train_scaled,
        X_test_scaled,
        df_train["target"].to_numpy(),
        df_test["target"].to_numpy(),
        scaler,
        feature_cols,
    )
