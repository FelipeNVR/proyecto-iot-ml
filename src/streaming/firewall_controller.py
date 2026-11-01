"""Controlador IPS de Cortafuegos (nftables/iptables/OpenWrt), Lista Blanca Anti-Lockout y Forense Z-Score."""

from typing import Dict, List, Set, Tuple
import numpy as np

# Lista blanca inmutable de infraestructura crítica (nunca pueden ser bloqueadas ni por IP Spoofing)
CRITICAL_WHITELIST_IPS: Set[str] = {
    "127.0.0.1",
    "192.168.1.1",   # Gateway Router Principal
    "192.168.1.10",  # Consola del Analista de Seguridad (SOC)
    "8.8.8.8",       # DNS Primario
    "1.1.1.1",       # DNS Secundario
}

# Direcciones MAC físicas asignadas a los 9 dispositivos del banco N-BaIoT
DEVICE_MACS: Dict[int, str] = {
    1: "00:16:6C:7B:9A:01",
    2: "44:61:32:1F:8C:02",
    3: "00:12:17:55:E1:03",
    4: "EC:1A:59:F0:33:04",
    5: "00:62:6E:4A:11:05",
    6: "00:62:6E:4A:12:06",
    7: "00:16:6C:8E:44:07",
    8: "7C:DD:90:A1:20:08",
    9: "7C:DD:90:A1:21:09",
}

# Perfiles de tráfico por dispositivo para Umbral Adaptativo (mitigación de FPR en cámaras HD)
HIGH_BANDWIDTH_CAMERA_DEVICES: Set[int] = {4, 5, 6, 7, 8, 9}


def get_adaptive_threshold(device_id: int, adaptive_enabled: bool = True) -> float:
    """
    Retorna el umbral de probabilidad P(Ataque | x) calibrado según el perfil físico del dispositivo:
      - Sensores de baja tasa (Timbres y Termostatos, Disp. 1-3): umbral estándar 0.50.
      - Cámaras IP y Monitores de Video HD (Disp. 4-9): umbral adaptativo 0.72 para evitar
        confundir ráfagas legítimas de video H.264 con ataques volumétricos (hallazgo LODO).
    """
    if not adaptive_enabled:
        return 0.50
    return 0.72 if int(device_id) in HIGH_BANDWIDTH_CAMERA_DEVICES else 0.50


def extract_root_cause_zscores(
    feat_scaled_1d: np.ndarray, feature_cols: List[str], top_k: int = 3
) -> str:
    """
    Extrae la explicación forense local de un paquete identificando las variables físicas
    cuyo Z-Score (desviaciones estándar respecto a la media normal) fue más extremo.
    """
    arr = np.asarray(feat_scaled_1d, dtype=np.float64).ravel()
    abs_z = np.abs(arr)
    top_indices = np.argsort(abs_z)[::-1][:top_k]

    parts = []
    for idx in top_indices:
        col_name = feature_cols[idx] if idx < len(feature_cols) else f"feat_{idx}"
        z_val = arr[idx]
        sign_str = "+" if z_val >= 0 else ""
        parts.append(f"{col_name} ({sign_str}{z_val:.1f}σ)")
    return " | ".join(parts)


def verify_whitelist_safety(ip_addr: str) -> Tuple[bool, str]:
    """Verifica que la IP objetivo no pertenezca a la Lista Blanca de infraestructura crítica."""
    ip_clean = str(ip_addr).strip()
    if ip_clean in CRITICAL_WHITELIST_IPS:
        return (
            False,
            f"BLOQUEO RECHAZADO POR LISTA BLANCA: La IP {ip_clean} es infraestructura crítica protegida contra IP Spoofing.",
        )
    return True, "OK"


def generate_firewall_commands(
    device_id: int, device_ip: str, attack_signature: str
) -> Dict[str, str]:
    """
    Genera los comandos exactos de mitigación a nivel de Capa 2 (MAC) y Capa 3/4 (IP/Conntrack)
    listos para ejecución en un Gateway Linux / OpenWrt / Raspberry Pi IPS.
    """
    mac_addr = DEVICE_MACS.get(int(device_id), "00:00:00:00:00:00")
    safe, msg = verify_whitelist_safety(device_ip)
    if not safe:
        return {"status": "BLOCKED_BY_WHITELIST", "reason": msg}

    return {
        "status": "READY",
        "device_mac": mac_addr,
        "device_ip": device_ip,
        "iptables_drop": (
            f"iptables -I FORWARD 1 -s {device_ip} -m mac --mac-source {mac_addr} "
            f'-m comment --comment "CINF200-IPS:{attack_signature}" -j DROP'
        ),
        "nftables_drop": (
            f"nft insert rule inet filter forward ip saddr {device_ip} "
            f'ether saddr {mac_addr} counter drop comment "CINF200-IPS:{attack_signature}"'
        ),
        "conntrack_flush": f"conntrack -D -s {device_ip}",
        "openwrt_uci_quarantine": (
            f"uci add firewall rule; uci set firewall.@rule[-1].name='Block_IoT_Dev{device_id}'; "
            f"uci set firewall.@rule[-1].src='lan'; uci set firewall.@rule[-1].src_ip='{device_ip}'; "
            f"uci set firewall.@rule[-1].src_mac='{mac_addr}'; uci set firewall.@rule[-1].target='DROP'; "
            f"uci commit firewall && /etc/init.d/firewall reload"
        ),
    }
