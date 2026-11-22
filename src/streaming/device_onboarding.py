"""Gestor dinámico de incorporación de nuevos dispositivos IoT e invitados.

Implementa dos mecanismos críticos para operación realista en redes domésticas:
1. Modo Aprendizaje 24h (Shadow Onboarding): al conectar un dispositivo IoT nuevo
   fuera del catálogo base, observa tráfico legítimo sin aplicar bloqueos
   automáticos y auto-calibra un umbral personal basado en el percentil 99.5
   de sus puntajes benignos observados (Q99.5 + margen).
2. Modo Concurrencia Social (Escenario Cumpleaños / Invitados): cuando múltiples
   equipos desconocidos se conectan en ráfaga (>= 3 equipos nuevos), los clasifica
   automáticamente en modo observación pasiva para evitar falsas alarmas masivas
   que desconecten a los invitados, manteniendo alerta pasiva ante ataques claros.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import numpy as np


@dataclass
class DynamicDeviceProfile:
    """Estado y parámetros de calibración de un dispositivo incorporado dinámicamente."""

    device_id: int
    name: str
    category: str
    ip: str
    mac: str
    profile_mode: str  # "LEARNING_24H", "PROTECTED", "GUEST_MONITOR_ONLY"
    target_samples: int = 20
    observed_benign_scores: List[float] = field(default_factory=list)
    personal_threshold: float = 0.75
    alerts_count: int = 0
    quarantined: bool = False
    false_alarms_avoided: int = 0
    calibrated_at_hours: float = 0.0

    @property
    def progress_pct(self) -> float:
        if self.profile_mode == "PROTECTED":
            return 100.0
        if self.profile_mode == "GUEST_MONITOR_ONLY":
            return 100.0
        return min(100.0, round((len(self.observed_benign_scores) / max(1, self.target_samples)) * 100.0, 1))


class DeviceOnboardingManager:
    """Administra el ciclo de vida de dispositivos desconocidos que ingresan a la red local."""

    BASE_CATALOG_COUNT = 9
    GUEST_BURST_THRESHOLD = 3
    MIN_THRESHOLD = 0.50
    MAX_THRESHOLD = 0.95
    SAFETY_MARGIN = 0.05
    GUEST_ALERT_THRESHOLD = 0.85

    def __init__(self):
        self.devices: Dict[int, DynamicDeviceProfile] = {}
        self.next_device_id: int = self.BASE_CATALOG_COUNT + 1
        self.social_event_active: bool = False

    def reset(self) -> None:
        """Limpia todos los dispositivos dinámicos incorporados."""
        self.devices.clear()
        self.next_device_id = self.BASE_CATALOG_COUNT + 1
        self.social_event_active = False

    def register_iot_device(
        self,
        name: str,
        category: str = "Cámara Wi-Fi nueva",
        target_samples: int = 20,
    ) -> DynamicDeviceProfile:
        """Registra un nuevo dispositivo IoT permanente en Modo Aprendizaje 24h (sin bloqueo prematuro)."""
        d_id = self.next_device_id
        self.next_device_id += 1
        profile = DynamicDeviceProfile(
            device_id=d_id,
            name=name,
            category=category,
            ip=f"192.168.1.{100 + d_id}",
            mac=f"AA:BB:CC:10:00:{d_id:02X}",
            profile_mode="LEARNING_24H",
            target_samples=max(5, int(target_samples)),
            personal_threshold=0.75,
        )
        self.devices[d_id] = profile
        return profile

    def register_guest_burst(self, count: int = 9) -> List[DynamicDeviceProfile]:
        """Registra una ráfaga de equipos visitantes (ej. cumpleaños con +9 invitados).

        Activa automáticamente el modo de concurrencia social para no bloquear
        el Wi-Fi de los invitados por tráfico multimedia/redes sociales legítimo.
        """
        guest_catalog = [
            ("iPhone Invitado 1", "Smartphone invitado"),
            ("Galaxy Invitado 2", "Smartphone invitado"),
            ("Pixel Invitado 3", "Smartphone invitado"),
            ("iPad Invitado 4", "Tablet invitado"),
            ("Xiaomi Invitado 5", "Smartphone invitado"),
            ("Laptop Invitado 6", "Portátil invitado"),
            ("iPhone Invitado 7", "Smartphone invitado"),
            ("Galaxy Invitado 8", "Smartphone invitado"),
            ("Smartwatch Invitado 9", "Wearable invitado"),
        ]
        created: List[DynamicDeviceProfile] = []
        if count >= self.GUEST_BURST_THRESHOLD:
            self.social_event_active = True

        for idx in range(count):
            d_id = self.next_device_id
            self.next_device_id += 1
            base_name, base_cat = guest_catalog[idx % len(guest_catalog)]
            if idx >= len(guest_catalog):
                base_name = f"Equipo Invitado {idx + 1}"
            profile = DynamicDeviceProfile(
                device_id=d_id,
                name=base_name,
                category=base_cat,
                ip=f"192.168.1.{100 + d_id}",
                mac=f"DE:AD:BE:20:00:{d_id:02X}",
                profile_mode="GUEST_MONITOR_ONLY",
                target_samples=0,
                personal_threshold=self.GUEST_ALERT_THRESHOLD,
            )
            self.devices[d_id] = profile
            created.append(profile)
        return created

    def observe_benign_score(self, device_id: int, anomaly_score: float) -> Optional[DynamicDeviceProfile]:
        """Alimenta una observación benigna durante el Modo Aprendizaje 24h.

        Si el puntaje habría disparado un umbral fijo 0.50, contabiliza una falsa alarma
        evitada gracias al periodo de observación. Al completar las muestras requeridas,
        auto-calibra el umbral personal (Q99.5 + margen) y promueve a PROTECTED.
        """
        prof = self.devices.get(device_id)
        if prof is None:
            return None

        score = float(np.clip(anomaly_score, 0.0, 1.0))
        if prof.profile_mode == "LEARNING_24H":
            prof.observed_benign_scores.append(score)
            if score >= self.MIN_THRESHOLD:
                prof.false_alarms_avoided += 1
            prof.calibrated_at_hours = min(
                24.0, round((len(prof.observed_benign_scores) / prof.target_samples) * 24.0, 1)
            )
            if len(prof.observed_benign_scores) >= prof.target_samples:
                q995 = float(np.percentile(prof.observed_benign_scores, 99.5))
                calibrated = max(self.MIN_THRESHOLD, q995 + self.SAFETY_MARGIN)
                prof.personal_threshold = round(
                    float(np.clip(calibrated, self.MIN_THRESHOLD, self.MAX_THRESHOLD)), 4
                )
                prof.profile_mode = "PROTECTED"
                prof.calibrated_at_hours = 24.0
        elif prof.profile_mode == "GUEST_MONITOR_ONLY":
            if self.MIN_THRESHOLD <= score < prof.personal_threshold:
                prof.false_alarms_avoided += 1
        return prof

    def evaluate_packet_policy(
        self,
        device_id: int,
        anomaly_score: float,
        auto_quarantine: bool = True,
    ) -> dict:
        """Decide la acción segura según el estado actual del dispositivo incorporado."""
        prof = self.devices.get(device_id)
        if prof is None:
            return {
                "verdict": "BENIGNO",
                "action": "Dispositivo no registrado",
                "blocked": False,
                "threshold": self.MIN_THRESHOLD,
            }

        score = float(np.clip(anomaly_score, 0.0, 1.0))

        # 1. En aprendizaje 24h: nunca bloquea automáticamente (fail-open seguro), solo alerta si score extremo
        if prof.profile_mode == "LEARNING_24H":
            if score >= 0.95:
                prof.alerts_count += 1
                return {
                    "verdict": "ALERTA_EN_APRENDIZAJE",
                    "action": "Alerta preventiva (Modo Aprendizaje 24h — sin auto-bloqueo)",
                    "blocked": False,
                    "threshold": prof.personal_threshold,
                }
            self.observe_benign_score(device_id, score)
            return {
                "verdict": "APRENDIENDO",
                "action": f"Observado para calibración ({prof.calibrated_at_hours:.1f}h / 24h)",
                "blocked": False,
                "threshold": prof.personal_threshold,
            }

        # 2. En modo invitado / cumpleaños: umbral conservador alto y solo alerta quirúrgica (no tumba Wi-Fi)
        if prof.profile_mode == "GUEST_MONITOR_ONLY":
            if score >= prof.personal_threshold:
                prof.alerts_count += 1
                return {
                    "verdict": "MALICIOSO",
                    "action": "Alerta quirúrgica en invitado (solo este equipo; resto de invitados sin cortes)",
                    "blocked": False,
                    "threshold": prof.personal_threshold,
                }
            if score >= self.MIN_THRESHOLD:
                prof.false_alarms_avoided += 1
            return {
                "verdict": "BENIGNO",
                "action": "Tráfico de invitado permitido (Modo Observación Social)",
                "blocked": False,
                "threshold": prof.personal_threshold,
            }

        # 3. En modo PROTECTED (ya calibrado tras 24h): protege con su umbral personal
        if score >= prof.personal_threshold:
            prof.alerts_count += 1
            if auto_quarantine:
                prof.quarantined = True
                return {
                    "verdict": "MALICIOSO",
                    "action": f"Aislado con umbral personal calibrado ({prof.personal_threshold:.4f})",
                    "blocked": True,
                    "threshold": prof.personal_threshold,
                }
            return {
                "verdict": "MALICIOSO",
                "action": "Alerta emitida (umbral personal superado)",
                "blocked": False,
                "threshold": prof.personal_threshold,
            }

        return {
            "verdict": "BENIGNO",
            "action": "Permitido dentro del perfil calibrado 24h",
            "blocked": False,
            "threshold": prof.personal_threshold,
        }

    def summary_rows(self) -> List[dict]:
        """Devuelve una lista de diccionarios lista para tablas de visualización."""
        rows = []
        mode_labels = {
            "LEARNING_24H": "Aprendizaje 24h",
            "PROTECTED": "Protegido (Calibrado)",
            "GUEST_MONITOR_ONLY": "Invitado (Solo monitoreo)",
        }
        for prof in self.devices.values():
            estado = "En cuarentena" if prof.quarantined else mode_labels.get(prof.profile_mode, prof.profile_mode)
            rows.append(
                {
                    "ID": prof.device_id,
                    "Dispositivo": prof.name,
                    "Tipo": prof.category,
                    "IP": prof.ip,
                    "MAC": prof.mac,
                    "Estado": estado,
                    "Calibración": f"{prof.progress_pct:.0f}%" if prof.profile_mode != "GUEST_MONITOR_ONLY" else "Modo social",
                    "Umbral personal": prof.personal_threshold,
                    "Falsas alarmas evitadas": prof.false_alarms_avoided,
                    "Alertas": prof.alerts_count,
                }
            )
        return rows
