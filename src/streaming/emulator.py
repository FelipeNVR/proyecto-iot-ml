"""Emulador del Capturador Central de Tráfico IoT a nivel de Enrutador (Traffic Mirroring)."""

import time
import os
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np


class IoTTrafficStreamEmulator:
    """
    Emulador del Capturador Central.
    Lee tráfico real pre-procesado del archivo stream_sample_real.csv (partición Test de N-BaIoT)
    e inyecta vectores de 115 características en tiempo real, respetando la probabilidad
    de anomalía (anomaly_prob) configurada en el Dashboard.
    """

    def __init__(
        self,
        n_features: int = 115,
        anomaly_prob: float = 0.15,
        stream_file: Optional[str] = None,
    ):
        self.n_features = n_features
        self.anomaly_prob = anomaly_prob
        self.packet_count = 0
        self.data_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "data")
        )
        self.stream_file = stream_file or os.path.join(
            self.data_dir, "stream_sample_real.csv"
        )

        self.df_stream: Optional[pd.DataFrame] = None
        self.df_benign: Optional[pd.DataFrame] = None
        self.df_attack: Optional[pd.DataFrame] = None
        self.feature_cols: List[str] = []
        self.benign_idx = 0
        self.attack_idx = 0

        if os.path.exists(self.stream_file):
            self.df_stream = pd.read_csv(self.stream_file)
            self.feature_cols = [
                c
                for c in self.df_stream.columns
                if c not in ["target", "attack_type", "device_id"]
            ]
            self.df_benign = self.df_stream[self.df_stream["target"] == 0].reset_index(
                drop=True
            )
            self.df_attack = self.df_stream[self.df_stream["target"] == 1].reset_index(
                drop=True
            )
            print(
                f"[EMULATOR] Cargadas {len(self.df_stream)} tramas reales de tráfico IoT "
                f"(Benignas={len(self.df_benign)}, Ataques={len(self.df_attack)})."
            )

    def stream_packet(self) -> Dict[str, Any]:
        """Emite un vector de 115 características muestreando según self.anomaly_prob."""
        self.packet_count += 1
        timestamp = time.strftime("%H:%M:%S")
        is_attack = bool(np.random.rand() < float(self.anomaly_prob))

        if (
            self.df_benign is not None
            and self.df_attack is not None
            and len(self.df_benign) > 0
            and len(self.df_attack) > 0
        ):
            if is_attack:
                row = self.df_attack.iloc[self.attack_idx % len(self.df_attack)]
                self.attack_idx += 1
            else:
                row = self.df_benign.iloc[self.benign_idx % len(self.df_benign)]
                self.benign_idx += 1

            attack_type = str(row.get("attack_type", "Benigno"))
            features = pd.DataFrame(
                [row[self.feature_cols].to_numpy(dtype=np.float64)],
                columns=self.feature_cols,
            )
            return {
                "packet_id": self.packet_count,
                "timestamp": timestamp,
                "simulated_ground_truth": attack_type,
                "is_attack_ground_truth": int(is_attack),
                "features": features,
            }

        # Fallback sintético controlado si aún no se ha generado stream_sample_real.csv
        attack_type = "Mirai_UDP" if is_attack else "Benigno"
        cols = (
            self.feature_cols
            if self.feature_cols
            else [f"feat_{i}" for i in range(self.n_features)]
        )
        raw_vals = np.random.normal(
            loc=80.0 if is_attack else 12.0,
            scale=10.0,
            size=(1, self.n_features),
        )
        features = pd.DataFrame(raw_vals, columns=cols)
        return {
            "packet_id": self.packet_count,
            "timestamp": timestamp,
            "simulated_ground_truth": attack_type,
            "is_attack_ground_truth": int(is_attack),
            "features": features,
        }
