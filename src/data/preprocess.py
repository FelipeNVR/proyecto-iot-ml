"""Módulo de ingesta, limpieza de artefactos Unix Epoch y partición temporal 70/15/15 en los 9 dispositivos N-BaIoT."""

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

DEVICE_IPS: Dict[int, str] = {
    1: "192.168.1.101",
    2: "192.168.1.102",
    3: "192.168.1.103",
    4: "192.168.1.104",
    5: "192.168.1.105",
    6: "192.168.1.106",
    7: "192.168.1.107",
    8: "192.168.1.108",
    9: "192.168.1.109",
}

META_COLS: List[str] = [
    "target",
    "attack_type",
    "device_id",
    "device_name",
    "device_ip",
    "source_csv",
]


def sanitize_jitter_features(df: pd.DataFrame) -> pd.DataFrame:
    """Elimina la fuga de datos (Data Leakage) por marca de tiempo Unix (~1.505e9 vs ~1.507e9 s)
    presente en las 10 columnas estadísticas HH_jit_*_mean y HH_jit_*_variance del extractor
    AfterImage (Kitsune) en N-BaIoT, preservando intactas las 5 columnas de conteo HH_jit_*_weight
    que no sufren contaminación del reloj Unix."""
    out = df.copy()
    contaminated_jit_cols = [
        c
        for c in out.columns
        if c.startswith("HH_jit_") and (c.endswith("_mean") or c.endswith("_variance"))
    ]
    if contaminated_jit_cols:
        out[contaminated_jit_cols] = 0.0
    return out


def chronological_split(
    df: pd.DataFrame,
    train_frac: float = 0.65,
    val_frac: float = 0.15,
    purge_frac: float = 0.025,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Divide un flujo secuencial en tres bloques temporales disjuntos separados por ventanas
    de purga (embargo temporal) para cortar la autocorrelación de las ventanas exponenciales (L0.01):
    - Primer 65% cronológico -> Entrenamiento (Train)
    - [Purga 2.5% descartada]
    - Siguiente 15% cronológico -> Validación (Val)
    - [Purga 2.5% descartada]
    - Último 15% cronológico -> Prueba independiente (Test)"""
    n = len(df)
    i_train_end = int(n * train_frac)
    i_val_start = int(n * (train_frac + purge_frac))
    i_val_end = int(n * (train_frac + purge_frac + val_frac))
    i_test_start = int(n * (train_frac + 2 * purge_frac + val_frac))
    return (
        df.iloc[:i_train_end].copy(),
        df.iloc[i_val_start:i_val_end].copy(),
        df.iloc[i_test_start:].copy(),
    )


def discover_attack_files(data_dir: str, device_id: int) -> List[str]:
    """Descubre dinámicamente todos los archivos CSV de ataque (gafgyt y mirai) de un dispositivo."""
    gafgyt_files = sorted(glob.glob(os.path.join(data_dir, f"{device_id}.gafgyt.*.csv")))
    mirai_files = sorted(glob.glob(os.path.join(data_dir, f"{device_id}.mirai.*.csv")))
    return gafgyt_files + mirai_files


def load_single_device_splits(
    data_dir: Optional[str] = None,
    device_id: int = 1,
    sample_benign: int = 3000,
    sample_attack: int = 3000,
    stabilize_jitter: bool = True,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Carga tráfico benigno y todos los subtipos de ataque disponibles (Mirai y BASHLITE)
    para un dispositivo específico, aplicando partición temporal 70/15/15 por cada captura."""
    if data_dir is None:
        data_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "data")
        )

    dev_name = DEVICE_NAMES.get(device_id, f"Device {device_id}")
    dev_ip = DEVICE_IPS.get(device_id, f"192.168.1.{100 + device_id}")
    benign_filename = f"{device_id}.benign.csv"
    benign_path = os.path.join(data_dir, benign_filename)
    if not os.path.exists(benign_path):
        raise FileNotFoundError(f"No se encontró el archivo benigno: {benign_path}")

    # 1. Cargar tráfico benigno en orden cronológico y separar 70/15/15
    df_benign = pd.read_csv(benign_path, nrows=sample_benign).copy()
    if stabilize_jitter:
        df_benign = sanitize_jitter_features(df_benign)
    df_benign = df_benign.assign(
        target=0,
        attack_type="Benigno",
        device_id=device_id,
        device_name=dev_name,
        device_ip=dev_ip,
        source_csv=benign_filename,
    )
    b_train, b_val, b_test = chronological_split(df_benign)
    b_train = b_train.assign(_rel_time=np.linspace(0.0, 1.0, len(b_train)))
    b_val = b_val.assign(_rel_time=np.linspace(0.0, 1.0, len(b_val)))
    b_test = b_test.assign(_rel_time=np.linspace(0.0, 1.0, len(b_test)))

    # 2. Descubrir dinámicamente todos los subtipos de ataque existentes para este dispositivo
    atk_paths = discover_attack_files(data_dir, device_id)
    if not atk_paths:
        raise FileNotFoundError(
            f"No se encontraron archivos de ataque para dispositivo {device_id}"
        )

    rows_per_attack = max(100, sample_attack // len(atk_paths))
    train_parts, val_parts, test_parts = [b_train], [b_val], [b_test]

    for atk_path in atk_paths:
        atk_filename = os.path.basename(atk_path)
        parts = atk_filename.replace(".csv", "").split(".")
        botnet = "BASHLITE" if parts[1] == "gafgyt" else "Mirai"
        atk_label = f"{botnet}_{parts[2].upper()}"

        df_atk = pd.read_csv(atk_path, nrows=rows_per_attack).copy()
        if stabilize_jitter:
            df_atk = sanitize_jitter_features(df_atk)
        df_atk = df_atk.assign(
            target=1,
            attack_type=atk_label,
            device_id=device_id,
            device_name=dev_name,
            device_ip=dev_ip,
            source_csv=atk_filename,
        )
        a_tr, a_va, a_te = chronological_split(df_atk)
        a_tr = a_tr.assign(_rel_time=np.linspace(0.0, 1.0, len(a_tr)))
        a_va = a_va.assign(_rel_time=np.linspace(0.0, 1.0, len(a_va)))
        a_te = a_te.assign(_rel_time=np.linspace(0.0, 1.0, len(a_te)))
        train_parts.append(a_tr)
        val_parts.append(a_va)
        test_parts.append(a_te)

    df_train = (
        pd.concat(train_parts, ignore_index=True)
        .sort_values("_rel_time", kind="mergesort")
        .drop(columns=["_rel_time"])
        .reset_index(drop=True)
    )
    df_val = (
        pd.concat(val_parts, ignore_index=True)
        .sort_values("_rel_time", kind="mergesort")
        .drop(columns=["_rel_time"])
        .reset_index(drop=True)
    )
    df_test = (
        pd.concat(test_parts, ignore_index=True)
        .sort_values("_rel_time", kind="mergesort")
        .drop(columns=["_rel_time"])
        .reset_index(drop=True)
    )

    for split_df in (df_train, df_val, df_test):
        split_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        split_df.dropna(inplace=True)

    print(
        f"[DATA] Disp. {device_id} ({dev_name}): "
        f"Train={len(df_train)}, Val={len(df_val)}, Test={len(df_test)} "
        f"| Subtipos ataque={len(atk_paths)}"
    )
    return df_train, df_val, df_test


def load_all_devices_for_lodo(
    data_dir: Optional[str] = None,
    sample_per_device: int = 3000,
    stabilize_jitter: bool = True,
) -> Dict[int, pd.DataFrame]:
    """Carga los 9 dispositivos de N-BaIoT para validación Leave-One-Device-Out (LODO)."""
    device_frames: Dict[int, pd.DataFrame] = {}
    for dev_id in range(1, 10):
        tr, va, te = load_single_device_splits(
            data_dir=data_dir,
            device_id=dev_id,
            sample_benign=sample_per_device // 2,
            sample_attack=sample_per_device // 2,
            stabilize_jitter=stabilize_jitter,
        )
        device_frames[dev_id] = pd.concat([tr, va, te], ignore_index=True)
    return device_frames


def load_device_data(
    data_dir: Optional[str] = None,
    device_id: Optional[int] = None,
    sample_benign: int = 2500,
    sample_attack: int = 2500,
    random_state: int = 42,
    stabilize_jitter: bool = True,
    return_val: bool = False,
    return_attack_types: bool = False,
):
    """Carga y escala sin data leakage los datos de los 9 dispositivos (si device_id es None)
    o de un dispositivo específico. Exporta además stream_sample_real.csv con trazas reales
    del conjunto de prueba (Test) de los 9 dispositivos y los 10 tipos de ataque."""
    if data_dir is None:
        data_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "data")
        )

    device_list = [device_id] if device_id is not None else list(range(1, 10))
    tr_list, va_list, te_list = [], [], []
    stream_parts = []

    for d_id in device_list:
        tr, va, te = load_single_device_splits(
            data_dir=data_dir,
            device_id=d_id,
            sample_benign=sample_benign,
            sample_attack=sample_attack,
            stabilize_jitter=stabilize_jitter,
        )
        tr_list.append(tr.assign(_rel_time=np.linspace(0.0, 1.0, len(tr))))
        va_list.append(va.assign(_rel_time=np.linspace(0.0, 1.0, len(va))))
        te_list.append(te.assign(_rel_time=np.linspace(0.0, 1.0, len(te))))

        # Seleccionar del conjunto TEST (nunca visto en entrenamiento) trazas reales
        # tanto benignas como de cada subtipo de ataque de este dispositivo
        te_benign = te[te["target"] == 0].head(40)
        stream_parts.append(te_benign)
        for atk_name, grp in te[te["target"] == 1].groupby("attack_type"):
            stream_parts.append(grp.head(15))

    # Intercalar los 9 dispositivos respetando estrictamente la progresión cronológica (sin shuffle temporal)
    df_train = (
        pd.concat(tr_list, ignore_index=True)
        .sort_values("_rel_time", kind="mergesort")
        .drop(columns=["_rel_time"])
        .reset_index(drop=True)
    )
    df_val = (
        pd.concat(va_list, ignore_index=True)
        .sort_values("_rel_time", kind="mergesort")
        .drop(columns=["_rel_time"])
        .reset_index(drop=True)
    )
    df_test = (
        pd.concat(te_list, ignore_index=True)
        .sort_values("_rel_time", kind="mergesort")
        .drop(columns=["_rel_time"])
        .reset_index(drop=True)
    )

    feature_cols: List[str] = [c for c in df_train.columns if c not in META_COLS]

    # Exportar stream_sample_real.csv con trazas 100% reales del conjunto Test de los 9 dispositivos
    if len(device_list) == 9:
        stream_sample = pd.concat(stream_parts, ignore_index=True)
        stream_path = os.path.join(data_dir, "stream_sample_real.csv")
        stream_sample.to_csv(stream_path, index=False)
        print(
            f"[DATA] Catálogo de trazas reales (Test) de los 9 dispositivos exportado en: "
            f"{stream_path} ({len(stream_sample)} filas reales)"
        )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(df_train[feature_cols])
    X_val_scaled = scaler.transform(df_val[feature_cols])
    X_test_scaled = scaler.transform(df_test[feature_cols])

    if return_val and return_attack_types:
        return (
            X_train_scaled,
            X_val_scaled,
            X_test_scaled,
            df_train["target"].to_numpy(),
            df_val["target"].to_numpy(),
            df_test["target"].to_numpy(),
            df_train["attack_type"].to_numpy(),
            df_test["attack_type"].to_numpy(),
            scaler,
            feature_cols,
        )

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


def load_distant_horizon_data(
    data_dir: Optional[str] = None,
    skip_rows: int = 10000,
    benign_per_device: int = 300,
    attack_per_file: int = 150,
    stabilize_jitter: bool = True,
) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Carga un horizonte temporal distante (ej. a partir de la fila 10.000 de cada CSV,
    completamente disjunto y alejado de las primeras 2.500 filas usadas en Train/Val/Test)
    para auditar empiricamente la resistencia a Concept Drift temporal.
    """
    if data_dir is None:
        data_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "data")
        )
    parts = []
    for d_id in range(1, 10):
        b_path = os.path.join(data_dir, f"{d_id}.benign.csv")
        if os.path.exists(b_path):
            df_b = pd.read_csv(b_path, skiprows=range(1, skip_rows), nrows=benign_per_device)
            if stabilize_jitter:
                df_b = sanitize_jitter_features(df_b)
            parts.append(df_b.assign(target=0))

        for a_path in discover_attack_files(data_dir, d_id)[:2]:
            df_a = pd.read_csv(a_path, skiprows=range(1, skip_rows), nrows=attack_per_file)
            if stabilize_jitter:
                df_a = sanitize_jitter_features(df_a)
            parts.append(df_a.assign(target=1))

    df_hor = pd.concat(parts, ignore_index=True)
    df_hor.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_hor.dropna(inplace=True)
    feature_cols = [c for c in df_hor.columns if c != "target"]
    return df_hor[feature_cols], df_hor["target"].to_numpy()
