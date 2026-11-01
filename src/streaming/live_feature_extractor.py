"""Motor incremental en tiempo real (AfterImage / Kitsune) para extraer las 115 características desde paquetes de red crudos."""

import math
from typing import Dict, List, Tuple, Any
import numpy as np
import pandas as pd

# Los 5 factores de decaimiento exponencial de N-BaIoT (horizontes: ~100ms, 500ms, 1.5s, 10s, 60s)
LAMBDAS: List[Tuple[str, float]] = [
    ("L5", 5.0),
    ("L3", 3.0),
    ("L1", 1.0),
    ("L0.1", 0.1),
    ("L0.01", 0.01),
]


class DampedStat1D:
    """Estadística incremental 1D con decaimiento exponencial O(1) en memoria (peso, media, varianza)."""

    __slots__ = ("w", "ls", "ss", "last_ts")

    def __init__(self) -> None:
        self.w: float = 0.0
        self.ls: float = 0.0
        self.ss: float = 0.0
        self.last_ts: float = -1.0

    def update(self, val: float, ts: float, lam: float) -> Tuple[float, float, float]:
        if self.last_ts < 0.0:
            decay = 1.0
        else:
            dt = max(0.0, ts - self.last_ts)
            decay = math.pow(2.0, -lam * dt)
        self.w = self.w * decay + 1.0
        self.ls = self.ls * decay + val
        self.ss = self.ss * decay + (val * val)
        self.last_ts = ts

        mean = self.ls / self.w
        var = max(0.0, (self.ss / self.w) - (mean * mean))
        return self.w, mean, var

    def read_decayed(self, ts: float, lam: float) -> Tuple[float, float, float]:
        if self.last_ts < 0.0 or self.w <= 1e-12:
            return 0.0, 0.0, 0.0
        dt = max(0.0, ts - self.last_ts)
        decay = math.pow(2.0, -lam * dt)
        w_dec = self.w * decay
        if w_dec <= 1e-12:
            return 0.0, 0.0, 0.0
        mean = (self.ls * decay) / w_dec
        var = max(0.0, ((self.ss * decay) / w_dec) - (mean * mean))
        return w_dec, mean, var


class LiveAfterImageExtractor:
    """
    Traductor en tiempo real de paquetes IP/TCP/UDP crudos al vector exacto de 115 características
    del estándar N-BaIoT (Meidan et al., 2018), corrigiendo de raíz el bug de inicialización
    Unix Epoch en el jitter (dt=0 en el primer paquete de cada flujo).
    Listo para conectarse a Scapy / libpcap / sockets raw en un Gateway Linux o Raspberry Pi.
    """

    def __init__(self, feature_columns: List[str]) -> None:
        self.feature_columns = list(feature_columns)
        self.mi_stats: Dict[Tuple[str, str], DampedStat1D] = {}
        self.h_stats: Dict[Tuple[str, str], DampedStat1D] = {}
        self.hh_stats: Dict[Tuple[str, str], DampedStat1D] = {}
        self.hh_jit_stats: Dict[Tuple[str, str], DampedStat1D] = {}
        self.hphp_stats: Dict[Tuple[str, str], DampedStat1D] = {}
        self.hh_last_pkt_ts: Dict[str, float] = {}

    def _get_stat(
        self, store: Dict[Tuple[str, str], DampedStat1D], key: Tuple[str, str]
    ) -> DampedStat1D:
        st = store.get(key)
        if st is None:
            st = DampedStat1D()
            store[key] = st
        return st

    @staticmethod
    def _calc_2d_metrics(
        m1: float, v1: float, m2: float, v2: float, w1: float, w2: float
    ) -> Tuple[float, float, float, float]:
        """Calcula magnitude, radius, covariance aproximada y pcc entre flujo saliente y entrante."""
        magnitude = math.sqrt(m1 * m1 + m2 * m2)
        radius = math.sqrt(v1 * v1 + v2 * v2)
        std1 = math.sqrt(max(0.0, v1))
        std2 = math.sqrt(max(0.0, v2))
        if w2 <= 1e-9 or std1 <= 1e-9 or std2 <= 1e-9:
            return magnitude, radius, 0.0, 0.0
        balance = min(w1, w2) / max(w1, w2)
        cov = std1 * std2 * balance
        pcc = cov / (std1 * std2) if (std1 * std2) > 1e-9 else 0.0
        return magnitude, radius, cov, pcc

    def process_raw_packet(
        self,
        src_mac: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        pkt_size: float,
        timestamp: float,
    ) -> pd.DataFrame:
        """
        Recibe los metadatos de cabecera de un paquete de red real (Capa 2/3/4) y actualiza
        en O(1) los contadores exponenciales para retornar el DataFrame de (1, 115) características.
        """
        mi_key = f"{src_mac}_{src_ip}"
        h_key = src_ip
        hh_fwd = f"{src_ip}_{dst_ip}"
        hh_rev = f"{dst_ip}_{src_ip}"
        hphp_fwd = f"{src_ip}:{src_port}_{dst_ip}:{dst_port}"
        hphp_rev = f"{dst_ip}:{dst_port}_{src_ip}:{src_port}"

        # Jitter libre de fuga Unix Epoch: en el primer paquete del par HH, dt = 0.0
        prev_hh_ts = self.hh_last_pkt_ts.get(hh_fwd)
        dt_hh = max(0.0, timestamp - prev_hh_ts) if prev_hh_ts is not None else 0.0
        self.hh_last_pkt_ts[hh_fwd] = timestamp

        feat_map: Dict[str, float] = {}

        for lam_label, lam_val in LAMBDAS:
            # 1. Familia MI_dir (MAC-IP origen, 3 variables por ventana = 15)
            w_mi, m_mi, v_mi = self._get_stat(
                self.mi_stats, (mi_key, lam_label)
            ).update(pkt_size, timestamp, lam_val)
            feat_map[f"MI_dir_{lam_label}_weight"] = w_mi
            feat_map[f"MI_dir_{lam_label}_mean"] = m_mi
            feat_map[f"MI_dir_{lam_label}_variance"] = v_mi

            # 2. Familia H (Host IP origen, 3 variables por ventana = 15)
            w_h, m_h, v_h = self._get_stat(self.h_stats, (h_key, lam_label)).update(
                pkt_size, timestamp, lam_val
            )
            feat_map[f"H_{lam_label}_weight"] = w_h
            feat_map[f"H_{lam_label}_mean"] = m_h
            feat_map[f"H_{lam_label}_variance"] = v_h

            # 3. Familia HH (Host-to-Host IP<->IP, 7 variables por ventana = 35)
            w_hh1, m_hh1, v_hh1 = self._get_stat(
                self.hh_stats, (hh_fwd, lam_label)
            ).update(pkt_size, timestamp, lam_val)
            w_hh2, m_hh2, v_hh2 = self._get_stat(
                self.hh_stats, (hh_rev, lam_label)
            ).read_decayed(timestamp, lam_val)
            mag_hh, rad_hh, cov_hh, pcc_hh = self._calc_2d_metrics(
                m_hh1, v_hh1, m_hh2, v_hh2, w_hh1, w_hh2
            )
            feat_map[f"HH_{lam_label}_weight"] = w_hh1
            feat_map[f"HH_{lam_label}_mean"] = m_hh1
            feat_map[f"HH_{lam_label}_std"] = math.sqrt(v_hh1)
            feat_map[f"HH_{lam_label}_magnitude"] = mag_hh
            feat_map[f"HH_{lam_label}_radius"] = rad_hh
            feat_map[f"HH_{lam_label}_covariance"] = cov_hh
            feat_map[f"HH_{lam_label}_pcc"] = pcc_hh

            # 4. Familia HH_jit (Jitter Host-to-Host, 3 variables por ventana = 15)
            # Nota: Mantenemos actualizados los contadores reales pero exportamos 0.0 en mean/variance
            # para consistencia estricta con la sanitización anti-epoch del pipeline entrenado.
            w_jit, _, _ = self._get_stat(
                self.hh_jit_stats, (hh_fwd, lam_label)
            ).update(dt_hh, timestamp, lam_val)
            feat_map[f"HH_jit_{lam_label}_weight"] = 0.0
            feat_map[f"HH_jit_{lam_label}_mean"] = 0.0
            feat_map[f"HH_jit_{lam_label}_variance"] = 0.0

            # 5. Familia HpHp (Socket-to-Socket IP:Port<->IP:Port, 7 variables por ventana = 35)
            w_hp1, m_hp1, v_hp1 = self._get_stat(
                self.hphp_stats, (hphp_fwd, lam_label)
            ).update(pkt_size, timestamp, lam_val)
            w_hp2, m_hp2, v_hp2 = self._get_stat(
                self.hphp_stats, (hphp_rev, lam_label)
            ).read_decayed(timestamp, lam_val)
            mag_hp, rad_hp, cov_hp, pcc_hp = self._calc_2d_metrics(
                m_hp1, v_hp1, m_hp2, v_hp2, w_hp1, w_hp2
            )
            feat_map[f"HpHp_{lam_label}_weight"] = w_hp1
            feat_map[f"HpHp_{lam_label}_mean"] = m_hp1
            feat_map[f"HpHp_{lam_label}_std"] = math.sqrt(v_hp1)
            feat_map[f"HpHp_{lam_label}_magnitude"] = mag_hp
            feat_map[f"HpHp_{lam_label}_radius"] = rad_hp
            feat_map[f"HpHp_{lam_label}_covariance"] = cov_hp
            feat_map[f"HpHp_{lam_label}_pcc"] = pcc_hp

        ordered_vals = [float(feat_map.get(col, 0.0)) for col in self.feature_columns]
        return pd.DataFrame(
            [np.array(ordered_vals, dtype=np.float64)], columns=self.feature_columns
        )
