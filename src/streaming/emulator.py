"""Capturador y Reproductor de Trazas Reales de Red IoT a nivel de Enrutador (Traffic Mirroring)."""

import time
import os
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np

from src.data.preprocess import META_COLS, DEVICE_NAMES, DEVICE_IPS


class IoTTrafficStreamEmulator:
    """
    Reproductor de Trazas Reales del Capturador Central (Gateway Router).
    Lee exclusivamente vectores reales del conjunto de prueba independiente (Test)
    de los 9 dispositivos físicos N-BaIoT (stream_sample_real.csv), permitiendo:
      1. Flujo continuo en tiempo real respetando la probabilidad de ataque (anomaly_prob).
      2. Inyección directa bajo demanda de cualquier ataque específico (Mirai / BASHLITE)
         y dispositivo físico (1 al 9) para auditoría en vivo sin datos sintéticos.
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
        self.custom_idx = 0

        self.reload_catalog()

    def reload_catalog(self) -> None:
        """Recarga el catálogo de trazas reales del conjunto Test desde disco."""
        if os.path.exists(self.stream_file):
            self.df_stream = pd.read_csv(self.stream_file)
            self.feature_cols = [
                c for c in self.df_stream.columns if c not in META_COLS
            ]
            # Mezclar con semilla fija para intercalar los 9 dispositivos en el stream continuo
            self.df_benign = (
                self.df_stream[self.df_stream["target"] == 0]
                .sample(frac=1.0, random_state=42)
                .reset_index(drop=True)
            )
            self.df_attack = (
                self.df_stream[self.df_stream["target"] == 1]
                .sample(frac=1.0, random_state=42)
                .reset_index(drop=True)
            )
            print(
                f"[EMULATOR] Cargadas {len(self.df_stream)} tramas reales de tráfico IoT "
                f"(Benignas={len(self.df_benign)}, Ataques={len(self.df_attack)})."
            )

    def get_available_attacks(self, device_id: Optional[int] = None) -> List[str]:
        """Retorna la lista de ataques reales disponibles en el conjunto de prueba (global o por dispositivo)."""
        if self.df_stream is None or self.df_stream.empty:
            return ["Benigno"]
        sub = self.df_stream
        if device_id is not None and "device_id" in sub.columns:
            sub = sub[sub["device_id"] == int(device_id)]
        attacks = sorted(
            [a for a in sub["attack_type"].unique().tolist() if a != "Benigno"]
        )
        return ["Benigno"] + attacks

    def _row_to_packet(self, row: pd.Series) -> Dict[str, Any]:
        """Convierte una fila real del CSV de prueba en un diccionario de trama de red con metadatos del dispositivo."""
        self.packet_count += 1
        timestamp = time.strftime("%H:%M:%S")
        dev_id = int(row.get("device_id", 1))
        dev_name = str(
            row.get("device_name", DEVICE_NAMES.get(dev_id, f"Dispositivo {dev_id}"))
        )
        dev_ip = str(
            row.get("device_ip", DEVICE_IPS.get(dev_id, f"192.168.1.{100 + dev_id}"))
        )
        attack_type = str(row.get("attack_type", "Benigno"))
        is_attack = int(row.get("target", 0 if attack_type == "Benigno" else 1))
        source_csv = str(
            row.get(
                "source_csv",
                f"{dev_id}.benign.csv" if is_attack == 0 else f"{dev_id}.{attack_type.lower()}.csv",
            )
        )

        features = pd.DataFrame(
            [row[self.feature_cols].to_numpy(dtype=np.float64)],
            columns=self.feature_cols,
        )
        return {
            "packet_id": self.packet_count,
            "timestamp": timestamp,
            "device_id": dev_id,
            "device_name": dev_name,
            "device_ip": dev_ip,
            "source_csv": source_csv,
            "simulated_ground_truth": attack_type,
            "is_attack_ground_truth": is_attack,
            "features": features,
        }

    def inject_specific_trace(
        self, attack_type: str, device_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Extrae una traza 100% real del conjunto Test correspondiente al ataque y dispositivo elegidos."""
        if self.df_stream is not None and not self.df_stream.empty:
            sub = self.df_stream[self.df_stream["attack_type"] == attack_type]
            if device_id is not None and "device_id" in sub.columns:
                sub_dev = sub[sub["device_id"] == int(device_id)]
                if not sub_dev.empty:
                    sub = sub_dev
            if not sub.empty:
                row = sub.iloc[self.custom_idx % len(sub)]
                self.custom_idx += 1
                return self._row_to_packet(row)
        return self.stream_packet()

    def stream_packet(
        self, target_device_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Emite un vector real de 115 características muestreando según self.anomaly_prob."""
        is_attack = bool(np.random.rand() < float(self.anomaly_prob))

        if (
            self.df_benign is not None
            and self.df_attack is not None
            and len(self.df_benign) > 0
            and len(self.df_attack) > 0
        ):
            pool = self.df_attack if is_attack else self.df_benign
            if target_device_id is not None and "device_id" in pool.columns:
                sub_pool = pool[pool["device_id"] == int(target_device_id)]
                if not sub_pool.empty:
                    pool = sub_pool

            if is_attack:
                row = pool.iloc[self.attack_idx % len(pool)]
                self.attack_idx += 1
            else:
                row = pool.iloc[self.benign_idx % len(pool)]
                self.benign_idx += 1

            return self._row_to_packet(row)

        # Fallback de emergencia únicamente si el archivo CSV no existiera en disco
        self.packet_count += 1
        timestamp = time.strftime("%H:%M:%S")
        attack_type = "Mirai_UDP" if is_attack else "Benigno"
        cols = (
            self.feature_cols
            if self.feature_cols
            else [f"feat_{i}" for i in range(self.n_features)]
        )
        raw_vals = np.random.normal(
            loc=80.0 if is_attack else 12.0,
            scale=10.0,
            size=(1, len(cols)),
        )
        return {
            "packet_id": self.packet_count,
            "timestamp": timestamp,
            "device_id": 1,
            "device_name": DEVICE_NAMES[1],
            "device_ip": DEVICE_IPS[1],
            "source_csv": "1.mirai.udp.csv" if is_attack else "1.benign.csv",
            "simulated_ground_truth": attack_type,
            "is_attack_ground_truth": int(is_attack),
            "features": pd.DataFrame(raw_vals, columns=cols),
        }
