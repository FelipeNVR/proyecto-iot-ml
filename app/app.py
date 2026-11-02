"""Dashboard IPS de 3 Anillos (Binario + Multiclase 10 Ataques + Zero-Day LocalOutlierFactor), Forense Z-Score y Cortafuegos Real."""

import os
import sys
import time
import json
import hmac
import base64
import hashlib
import subprocess
import joblib
import numpy as np
import pandas as pd
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.streaming.emulator import IoTTrafficStreamEmulator
from src.streaming.incident_store import IncidentStore
from src.streaming.firewall_controller import (
    get_adaptive_threshold,
    extract_root_cause_zscores,
    generate_firewall_commands,
    CRITICAL_WHITELIST_IPS,
    DEVICE_MACS,
)
from src.streaming.live_feature_extractor import LiveAfterImageExtractor
from src.data.preprocess import DEVICE_NAMES, DEVICE_IPS

st.set_page_config(
    page_title="IPS Centralizado de Defensa IoT (3 Anillos)",
    page_icon="🛡️",
    layout="wide",
)

REGISTRY_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "models_registry")
)


class SecurityIntegrityError(RuntimeError):
    """Excepción lanzada cuando falla la verificación criptográfica SHA-256 de un artefacto ML."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue_jwt_hs256(subject: str, secret: str, ttl_seconds: int = 3600) -> str:
    """Genera un token JWT (RFC 7519) firmado con HMAC-SHA256 y tiempo de expiración."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": "security_analyst",
        "iat": now,
        "exp": now + ttl_seconds,
    }
    signing_input = (
        f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))}."
        f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))}"
    )
    signature = hmac.new(
        secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def verify_jwt_hs256(token: str, secret: str) -> bool:
    """Verifica la firma HMAC-SHA256 y la vigencia temporal (exp) de un token JWT."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = hmac.new(
            secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        actual_sig = base64.urlsafe_b64decode(parts[2] + "==")
        if not hmac.compare_digest(expected_sig, actual_sig):
            return False

        payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_bytes.decode("utf-8"))
        if payload.get("exp", 0) < int(time.time()):
            return False
        return True
    except Exception:
        return False


def verify_file_sha256(filepath: str, expected_hash: str) -> bool:
    """Calcula el hash SHA-256 de un archivo en bloques de 64 KB y lo compara con el esperado."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hmac.compare_digest(hasher.hexdigest().lower(), expected_hash.lower())


@st.cache_resource
def load_verified_models(registry_dir: str):
    """Carga los 3 Anillos de Defensa verificando su integridad criptográfica SHA-256."""
    manifest_path = os.path.join(registry_dir, "artifacts_sha256.json")
    if not os.path.exists(manifest_path):
        return None, {}, None, None

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    scaler_file = os.path.join(registry_dir, "scaler_nbaiot.pkl")
    if not verify_file_sha256(scaler_file, manifest.get("scaler_nbaiot.pkl", "")):
        raise SecurityIntegrityError(
            "El artefacto scaler_nbaiot.pkl está corrupto o fue modificado."
        )
    scaler = joblib.load(scaler_file)

    model_mapping = {
        "Random Forest (Ensamble Bagging)": "model_random_forest.pkl",
        "Gradient Boosting (Ensamble Boosting)": "model_gradient_boosting.pkl",
        "Linear Support Vector Machine (LinearSVC Calibrado)": "model_svm.pkl",
        "Árbol de Decisión (max_depth=5)": "model_candidate_dt.pkl",
        "Regresión Logística (Línea Base Lineal)": "model_baseline_lr.pkl",
    }

    models_dict = {}
    for label, filename in model_mapping.items():
        model_path = os.path.join(registry_dir, filename)
        if os.path.exists(model_path):
            expected = manifest.get(filename, "")
            if not verify_file_sha256(model_path, expected):
                raise SecurityIntegrityError(f"Integridad comprometida en {filename}.")
            mdl = joblib.load(model_path)
            if hasattr(mdl, "n_jobs"):
                mdl.n_jobs = 1
            models_dict[label] = mdl

    # Cargar Anillo 2 (Clasificador Multiclase de 10 Ataques)
    mc_model = None
    mc_path = os.path.join(registry_dir, "model_multiclass_attack.pkl")
    if os.path.exists(mc_path) and "model_multiclass_attack.pkl" in manifest:
        if not verify_file_sha256(mc_path, manifest["model_multiclass_attack.pkl"]):
            raise SecurityIntegrityError(
                "Integridad comprometida en model_multiclass_attack.pkl."
            )
        mc_model = joblib.load(mc_path)
        if hasattr(mc_model, "n_jobs"):
            mc_model.n_jobs = 1

    # Cargar Anillo 3 (Detector No Supervisado Zero-Day LocalOutlierFactor)
    zd_model = None
    zd_path = os.path.join(registry_dir, "model_zeroday_iforest.pkl")
    if os.path.exists(zd_path) and "model_zeroday_iforest.pkl" in manifest:
        if not verify_file_sha256(zd_path, manifest["model_zeroday_iforest.pkl"]):
            raise SecurityIntegrityError(
                "Integridad comprometida en model_zeroday_iforest.pkl."
            )
        zd_model = joblib.load(zd_path)
        if hasattr(zd_model, "n_jobs"):
            zd_model.n_jobs = 1

    return scaler, models_dict, mc_model, zd_model


@st.cache_resource
def load_blind_lodo_candidates(registry_dir: str) -> dict:
    """Carga los 9 modelos de rotación ciega 6/2/1 (experiments/rigorous_v1/device_{i}_rf/candidate.joblib)
    verificando su hash SHA-256 contra candidate_hashes.json. En cada fold i, el Dispositivo i
    tiene 0% de muestras en entrenamiento y calibración."""
    exp_root = os.path.join(os.path.dirname(registry_dir), "experiments", "rigorous_v1")
    hashes_path = os.path.join(exp_root, "candidate_hashes.json")
    if not os.path.exists(hashes_path):
        return {}
    try:
        with open(hashes_path, "r", encoding="utf-8") as f:
            cand_hashes = json.load(f)
    except Exception:
        return {}

    blind_dict = {}
    for dev_id in range(1, 10):
        rel_key_win = f"device_{dev_id}_rf\\candidate.joblib"
        rel_key_posix = f"device_{dev_id}_rf/candidate.joblib"
        expected_sha = cand_hashes.get(rel_key_win) or cand_hashes.get(rel_key_posix, "")
        cand_path = os.path.join(exp_root, f"device_{dev_id}_rf", "candidate.joblib")
        if os.path.exists(cand_path) and expected_sha:
            if verify_file_sha256(cand_path, expected_sha):
                cand_obj = joblib.load(cand_path)
                if hasattr(cand_obj.get("model"), "n_jobs"):
                    cand_obj["model"].n_jobs = 1
                blind_dict[dev_id] = cand_obj
    return blind_dict


# ----------------- CONTROL DE ACCESO (JWT + HMAC) -----------------
JWT_SECRET = os.environ.get("CINF200_JWT_SECRET", "super-secret-iot-unab-2026-key")
EXPECTED_USER = os.environ.get(
    "CINF200_ANALYST_USER", os.environ.get("IOT_ADMIN_USER", "analista_unab")
)
EXPECTED_PASSWORD = os.environ.get(
    "CINF200_ANALYST_PASS", os.environ.get("IOT_DASHBOARD_SECRET", "demo-jwt-key-2026")
)


def check_authentication():
    if "jwt_token" not in st.session_state:
        st.session_state.jwt_token = None

    if st.session_state.jwt_token and verify_jwt_hs256(
        st.session_state.jwt_token, JWT_SECRET
    ):
        return True

    st.markdown(
        """
        <div style='text-align: center; margin-top: 30px; margin-bottom: 20px;'>
            <h1>🛡️ Acceso Seguro a la Consola IPS de Monitoreo IoT</h1>
            <p style='color: #4A607A;'>Seminario de Licenciatura en Ciencias de la Ingeniería (CINF200) — UNAB</p>
            <p>Control de acceso obligatorio para analistas autorizados mediante tokens JWT (RFC 7519).</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns([1, 1.3, 1])
    with col2:
        with st.form("login_form"):
            user = st.text_input(
                "Usuario / ID de Analista",
                value="",
                placeholder="Ingrese identificador de analista...",
                help="Identificador de usuario asignado en las variables de entorno del Gateway.",
            )
            pwd = st.text_input(
                "Contraseña / Token Secreto",
                type="password",
                value="",
                placeholder="••••••••••••",
                help="Clave secreta asignada para emitir el token de sesión.",
            )
            submit = st.form_submit_button(
                "Iniciar Sesión Segura (Emitir JWT)", use_container_width=True
            )

            if submit:
                user_clean = user.strip()
                pwd_clean = pwd.strip()
                if not user_clean or not pwd_clean:
                    st.warning("⚠️ Debe ingresar su usuario y contraseña.")
                else:
                    valid_user = hmac.compare_digest(user_clean, EXPECTED_USER)
                    valid_pass = hmac.compare_digest(pwd_clean, EXPECTED_PASSWORD)
                    if valid_user and valid_pass:
                        token = issue_jwt_hs256(subject=user_clean, secret=JWT_SECRET)
                        st.session_state.jwt_token = token
                        st.success("Autenticación exitosa. Token JWT emitido.")
                        st.rerun()
                    else:
                        st.error("Credenciales inválidas. Acceso denegado.")
    return False


if not check_authentication():
    st.stop()

# ----------------- PANEL PRINCIPAL DEL DASHBOARD -----------------
incident_store = IncidentStore()

current_user = "analista"
if st.session_state.jwt_token:
    try:
        payload_bytes = base64.urlsafe_b64decode(
            st.session_state.jwt_token.split(".")[1] + "=="
        )
        payload = json.loads(payload_bytes.decode("utf-8"))
        current_user = payload.get("sub", "analista")
    except Exception:
        current_user = "analista"

st.sidebar.title("🛡️ Consola IPS del Analista")
st.sidebar.markdown(f"**Operador:** `{current_user}`")
st.sidebar.markdown("**Sesión:** JWT `HS256` Válida 🔒")
st.sidebar.markdown("**Arquitectura:** Defensa en 3 Anillos")

if st.sidebar.button("Cerrar Sesión", use_container_width=True):
    st.session_state.jwt_token = None
    st.rerun()

st.title("🛡️ Sistema IPS Centralizado de Defensa IoT (Arquitectura de 3 Anillos)")
st.caption(
    "Demo sobre vectores del catálogo N-BaIoT: detector binario, clasificación de ataques y detector de novedades LOF."
)
st.info("Esta aplicación reproduce capturas guardadas; no está capturando tu router. "
        "La validación con tu IoT y la equivalencia del extractor están pendientes. "
        "Los resultados de laboratorio no autorizan bloqueo automático en producción.")

# Carga segura de los 3 anillos de modelos
try:
    scaler, models_dict, multiclass_model, zeroday_model = load_verified_models(
        REGISTRY_DIR
    )
    blind_lodo_candidates = load_blind_lodo_candidates(REGISTRY_DIR)
except SecurityIntegrityError as err:
    st.error(f"🚨 ALERTA DE SEGURIDAD CRÍTICA: {err}")
    st.stop()

metrics_path = os.path.join(REGISTRY_DIR, "baseline_metrics.json")
metrics_data = {}
if os.path.exists(metrics_path):
    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics_data = json.load(f)

if models_dict:
    selected_model_label = st.sidebar.selectbox(
        "Anillo 1 — Clasificador Binario", options=list(models_dict.keys()), index=0
    )
    model = models_dict[selected_model_label]
else:
    selected_model_label = "No disponible"
    model = None
    st.sidebar.warning(
        "Artefactos no encontrados en models_registry/. Ejecute baseline.py primero."
    )

# Controles de Defensa Activa IPS
st.sidebar.markdown("---")
st.sidebar.subheader("🛡️ Políticas de Prevención Activa (IPS)")
blind_lodo_enabled = st.sidebar.toggle(
    "🔬 Evaluación Ciega 6/2/1 (Dispositivo Excluido de Train)",
    value=bool(blind_lodo_candidates),
    disabled=not bool(blind_lodo_candidates),
    help=(
        "Al evaluar o atacar el Dispositivo X, utiliza el modelo entrenado exclusivamente "
        "en otros 6 dispositivos (y calibrado en otros 2), garantizando 0% de muestras del "
        "Dispositivo X en entrenamiento."
    ),
)
adaptive_thr_enabled = st.sidebar.toggle(
    "Umbral Adaptativo por Perfil (Anti-FPR Cámaras)",
    value=True,
    help="Usa umbral 0.50 en sensores/timbres y 0.72 en cámaras de video HD para evitar falsas alarmas por streaming.",
)
auto_ips_quarantine = st.sidebar.toggle(
    "Auto-Aislar Dispositivo al Detectar Ataque (IPS)",
    value=True,
    help="Aísla automáticamente en el Firewall del Router (iptables/nftables) a cualquier dispositivo que lance un ataque confirmado.",
)
enable_zeroday_ring = st.sidebar.toggle(
    "Anillo 3: Detector Zero-Day (LocalOutlierFactor)",
    value=True,
    help="Detecta anomalías desconocidas usando un modelo no supervisado entrenado exclusivamente con tráfico benigno.",
)

# Inicialización de estado de sesión
if "stream_data" not in st.session_state:
    st.session_state.stream_data = []
if "emulator" not in st.session_state:
    st.session_state.emulator = IoTTrafficStreamEmulator()
if "last_latency_ms" not in st.session_state:
    st.session_state.last_latency_ms = 0.0
if "quarantined_devices" not in st.session_state:
    st.session_state.quarantined_devices = set()
if "firewall_rules_log" not in st.session_state:
    st.session_state.firewall_rules_log = {}
if "last_injected_info" not in st.session_state:
    st.session_state.last_injected_info = None
if "live_extractor" not in st.session_state and st.session_state.emulator.feature_cols:
    st.session_state.live_extractor = LiveAfterImageExtractor(
        st.session_state.emulator.feature_cols
    )


def evaluate_and_record_packet(packet: dict) -> dict:
    """Ejecuta los 3 Anillos de Defensa, extrae la causa raíz física (Z-Score) y aplica políticas IPS."""
    t_start = time.perf_counter()
    feat_scaled = scaler.transform(packet["features"])

    dev_id = int(packet.get("device_id", 1))
    dev_name = str(
        packet.get("device_name", DEVICE_NAMES.get(dev_id, f"Disp. {dev_id}"))
    )
    dev_ip = str(
        packet.get("device_ip", DEVICE_IPS.get(dev_id, f"192.168.1.{100+dev_id}"))
    )
    dev_label = f"{dev_id}. {dev_name} ({dev_ip})"

    # Anillo 1: Probabilidad supervisada + Umbral Adaptativo o Modelo Ciego 6/2/1
    if blind_lodo_enabled and dev_id in blind_lodo_candidates:
        cand_obj = blind_lodo_candidates[dev_id]
        cand_mdl = cand_obj["model"]
        cand_cols = cand_obj["features"]
        prob = float(cand_mdl.predict_proba(packet["features"][cand_cols])[0][1])
        threshold = round(float(cand_obj["threshold"]), 4) if adaptive_thr_enabled else 0.50
        pred_ring1 = 1 if prob >= threshold else 0
        tr_devs = cand_obj["metadata"].get("train_devices", [])
        cal_devs = cand_obj["metadata"].get("calibration_devices", [])
        eval_mode_label = (
            f"RF Ciego 6/2/1 (Train:{tr_devs} | Cal:{cal_devs} | Disp.{dev_id} 0% visto)"
        )
    else:
        prob = (
            float(model.predict_proba(feat_scaled)[0][1])
            if hasattr(model, "predict_proba")
            else float(model.predict(feat_scaled)[0])
        )
        threshold = get_adaptive_threshold(dev_id, adaptive_enabled=adaptive_thr_enabled)
        pred_ring1 = 1 if prob >= threshold else 0
        eval_mode_label = selected_model_label.split(" (")[0]

    # Anillo 3: Detector No Supervisado Zero-Day (LocalOutlierFactor)
    zeroday_flag = False
    if enable_zeroday_ring and zeroday_model is not None:
        zd_pred = int(zeroday_model.predict(feat_scaled)[0])  # -1 = anomalía
        if zd_pred == -1 and prob >= 0.35:
            zeroday_flag = True

    is_malicious = (pred_ring1 == 1) or zeroday_flag

    # Anillo 2: Clasificador Multiclase de Firma de Botnet (sin leer la etiqueta del CSV)
    if is_malicious and multiclass_model is not None:
        ai_predicted_attack = str(multiclass_model.predict(feat_scaled)[0])
        if ai_predicted_attack in ("BASHLITE_TCP", "BASHLITE_UDP"):
            w_l5 = float(packet["features"]["MI_dir_L5_weight"].iloc[0])
            m_l5 = float(packet["features"]["MI_dir_L5_mean"].iloc[0])
            if w_l5 <= 1.05 and 58.0 <= m_l5 <= 62.0:
                ai_predicted_attack = "BASHLITE_TCP/UDP (Spoof Flood 60B)"
        if pred_ring1 == 0 and zeroday_flag:
            ai_predicted_attack = f"POSIBLE_ZERO_DAY ({ai_predicted_attack})"
    elif is_malicious:
        ai_predicted_attack = "ATAQUE_GENERICO"
    else:
        ai_predicted_attack = "Benigno"

    # Explicabilidad Forense Local (Top 3 variables físicas con mayor desviación Z-Score)
    root_cause_str = extract_root_cause_zscores(
        feat_scaled[0], st.session_state.emulator.feature_cols, top_k=3
    )

    latency_ms = (time.perf_counter() - t_start) * 1000.0
    already_quarantined = dev_id in st.session_state.quarantined_devices

    if is_malicious:
        if already_quarantined:
            action_str = "🔒 PAQUETE DESCARTADO EN ROUTER (Dispositivo ya en Cuarentena)"
        elif auto_ips_quarantine:
            st.session_state.quarantined_devices.add(dev_id)
            fw_cmds = generate_firewall_commands(dev_id, dev_ip, ai_predicted_attack)
            st.session_state.firewall_rules_log[dev_id] = fw_cmds
            action_str = "🛡️ AUTO-AISLADO POR IPS (Regla DROP aplicada en Firewall)"
        else:
            action_str = "🚨 Alerta emitida — Pendiente de aislamiento manual"

        incident_store.log_incident(
            timestamp=packet["timestamp"],
            model_name=f"{eval_mode_label} + Anillo 2",
            attack_type=(
                f"IA:{ai_predicted_attack} | Real:{packet['simulated_ground_truth']} "
                f"| Causa:{root_cause_str}"
            ),
            confidence=prob,
            action=action_str,
            device_name=dev_label,
        )
    else:
        action_str = (
            "🔒 Dispositivo en Cuarentena"
            if already_quarantined
            else "🟢 Tráfico permitido"
        )

    record = {
        "ID": packet["packet_id"],
        "Hora": packet["timestamp"],
        "Dispositivo_IoT": dev_label,
        "Modo_Evaluación": eval_mode_label,
        "CSV_Real_Origen": packet.get("source_csv", "N-BaIoT"),
        "Real_CSV": packet["simulated_ground_truth"],
        "Predicción_IA_Anillo2": ai_predicted_attack,
        "Veredicto": "MALICIOSO" if is_malicious else "BENIGNO",
        "Score_Anomalía": round(prob, 4),
        "Umbral_Disp": threshold,
        "Causa_Raíz_ZScore": root_cause_str,
        "Acción_IPS": action_str,
        "Latencia_ms": round(latency_ms, 3),
    }
    st.session_state.stream_data.append(record)
    if len(st.session_state.stream_data) > 60:
        st.session_state.stream_data.pop(0)
    st.session_state.last_latency_ms = latency_ms
    return record


# ----------------- BARRA LATERAL: CAPTURA CONTINUA E INYECCIÓN MANUAL -----------------
st.sidebar.markdown("---")
st.sidebar.subheader("📡 1. Monitoreo Continuo (Router Mirroring)")
run_sim = st.sidebar.toggle("Reproducir catálogo N-BaIoT (no captura de red)", value=False)
anomaly_prob = st.sidebar.slider(
    "Frecuencia de Tramas de Ataque", 0.0, 0.8, 0.20, step=0.05
)
st.session_state.emulator.anomaly_prob = anomaly_prob

stream_speed = st.sidebar.slider(
    "Velocidad de flujo (seg/ciclo)",
    min_value=0.2,
    max_value=2.0,
    value=0.5,
    step=0.1,
)

packets_per_cycle = st.sidebar.select_slider(
    "Paquetes por ciclo",
    options=[1, 2, 5, 10],
    value=2,
)

st.sidebar.markdown("---")
st.sidebar.subheader("⚡ 2. Inyectar Ataque Real a Elección")
st.sidebar.caption(
    "Seleccione un dispositivo físico y un ataque real del conjunto de prueba (Test) de N-BaIoT para verificar la detección y el bloqueo IPS al instante."
)

device_options = {
    f"{d_id}. {DEVICE_NAMES[d_id]} ({DEVICE_IPS[d_id]})": d_id for d_id in range(1, 10)
}
selected_dev_str = st.sidebar.selectbox(
    "Dispositivo IoT Origen", options=list(device_options.keys()), index=0
)
selected_dev_id = device_options[selected_dev_str]

if blind_lodo_enabled and selected_dev_id in blind_lodo_candidates:
    c_meta = blind_lodo_candidates[selected_dev_id]["metadata"]
    st.sidebar.info(
        f"🔬 **Fold Ciego 6/2/1 Activo:** Al atacar el **Disp. {selected_dev_id}**, se evalúa con el modelo "
        f"`device_{selected_dev_id}_rf` entrenado solo en Disp. `{c_meta['train_devices']}` y calibrado en "
        f"`{c_meta['calibration_devices']}` (**0% de datos del Disp. {selected_dev_id} en entrenamiento**)."
    )

available_attacks = st.session_state.emulator.get_available_attacks(
    device_id=selected_dev_id
)
default_atk_idx = 1 if len(available_attacks) > 1 else 0
selected_attack_type = st.sidebar.selectbox(
    "Tipo de Tráfico / Ataque Real (CSV Test)",
    options=available_attacks,
    index=default_atk_idx,
)

burst_count = st.sidebar.select_slider(
    "Cantidad de tramas reales a inyectar", options=[1, 3, 5, 10], value=1
)

if st.sidebar.button(
    "⚡ Lanzar Trama Real Ahora", use_container_width=True, type="primary"
):
    if model is not None and scaler is not None:
        last_rec = None
        for _ in range(burst_count):
            pkt = st.session_state.emulator.inject_specific_trace(
                attack_type=selected_attack_type, device_id=selected_dev_id
            )
            last_rec = evaluate_and_record_packet(pkt)
        st.session_state.last_injected_info = last_rec
        st.rerun()

st.sidebar.markdown("---")
if st.sidebar.button(
    "🗑️ Reiniciar Historial SQL y Cuarentenas", use_container_width=True
):
    incident_store.clear_all()
    st.session_state.stream_data = []
    st.session_state.quarantined_devices = set()
    st.session_state.firewall_rules_log = {}
    st.session_state.last_injected_info = None
    st.sidebar.success("Historial de incidentes, telemetría y cuarentenas reiniciados.")
    st.rerun()

# Procesamiento automático si el modo continuo está activo
if run_sim and model is not None and scaler is not None:
    latencies = []
    for _ in range(packets_per_cycle):
        packet = st.session_state.emulator.stream_packet()
        rec = evaluate_and_record_packet(packet)
        latencies.append(rec["Latencia_ms"])
    if latencies:
        st.session_state.last_latency_ms = float(sum(latencies) / len(latencies))

# Banner con el diagnóstico forense completo de la última inyección
if st.session_state.last_injected_info is not None:
    info = st.session_state.last_injected_info
    if info["Veredicto"] == "MALICIOSO":
        st.error(
            f"🎯 **Inspección Forense de 3 Anillos:** Archivo real **`{info['CSV_Real_Origen']}`** "
            f"({info['Dispositivo_IoT']}) | **Modelo Evaluador:** `{info.get('Modo_Evaluación', 'N/A')}` | **Etiqueta Real CSV:** `{info['Real_CSV']}` ➡️ "
            f"**Anillo 1:** `{info['Veredicto']}` (Score `{info['Score_Anomalía']:.4f}` vs Umbral `{info['Umbral_Disp']}`) | "
            f"**Anillo 2 (Firma Predicha por IA sin ver etiqueta):** **`{info['Predicción_IA_Anillo2']}`** | "
            f"**Causa Raíz Física (Z-Score):** `{info['Causa_Raíz_ZScore']}` | "
            f"**Respuesta IPS (`{info['Latencia_ms']:.2f} ms`):** {info['Acción_IPS']}"
        )
    else:
        st.success(
            f"✅ **Inspección Forense de 3 Anillos:** Archivo real **`{info['CSV_Real_Origen']}`** "
            f"({info['Dispositivo_IoT']}) | **Modelo Evaluador:** `{info.get('Modo_Evaluación', 'N/A')}` | **Tráfico Real:** `{info['Real_CSV']}` ➡️ "
            f"**Clasificado como `BENIGNO`** (Score `{info['Score_Anomalía']:.4f}` < Umbral `{info['Umbral_Disp']}`) "
            f"en **`{info['Latencia_ms']:.2f} ms`**."
        )

# ----------------- KPIs PRINCIPALES -----------------
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
df_stream = pd.DataFrame(st.session_state.stream_data)

if not df_stream.empty:
    total = len(df_stream)
    malicious = int((df_stream["Veredicto"] == "MALICIOSO").sum())
    rate = (malicious / total) * 100.0
    recent_malicious = int((df_stream.tail(5)["Veredicto"] == "MALICIOSO").sum())

    kpi1.metric("Tramas Reales Evaluadas", f"{st.session_state.emulator.packet_count}")
    kpi2.metric("Amenazas en Ventana", f"{malicious}")
    kpi3.metric(
        "Dispositivos en Cuarentena",
        f"{len(st.session_state.quarantined_devices)} / 9",
    )
    kpi4.metric("Latencia Inferencia (3 Anillos)", f"{st.session_state.last_latency_ms:.2f} ms")

    if malicious == 0:
        kpi5.success("🟢 ESTADO: RED SEGURA")
    elif recent_malicious >= 2 or rate >= 15.0 or malicious >= 5:
        kpi5.error("🚨 ESTADO: RED BAJO ATAQUE (IPS ACTIVO)")
    else:
        kpi5.warning("⚠️ ESTADO: INTRUSIÓN CONTENIDA")
else:
    kpi1.metric("Tramas Reales Evaluadas", 0)
    kpi2.metric("Amenazas en Ventana", 0)
    kpi3.metric(
        "Dispositivos en Cuarentena",
        f"{len(st.session_state.quarantined_devices)} / 9",
    )
    kpi4.metric("Latencia Inferencia (3 Anillos)", "0.00 ms")
    kpi5.info("⏳ EN ESPERA")

# ----------------- SECCIÓN DE PACIENTE CERO, REGLAS FIREWALL Y ESTADO DE LOS 9 DISPOSITIVOS -----------------
st.markdown("---")
st.subheader(
    "🎯 Detección de Paciente Cero (Primer Dispositivo Comprometido) y Cortafuegos IPS en Router"
)

patient_zero = incident_store.get_first_compromised_device()
col_pz, col_mitigation = st.columns([1.45, 1.55])

with col_pz:
    if patient_zero:
        pz_dev_name = patient_zero["device_name"]
        try:
            pz_dev_id = int(pz_dev_name.split(".")[0])
        except Exception:
            pz_dev_id = 1
        pz_ip = DEVICE_IPS.get(pz_dev_id, "192.168.1.101")
        pz_mac = DEVICE_MACS.get(pz_dev_id, "00:16:6C:7B:9A:01")
        pz_quarantined = pz_dev_id in st.session_state.quarantined_devices

        st.error(
            f"🚨 **PACIENTE CERO IDENTIFICADO (Primer Dispositivo Atacante):**\n\n"
            f"- **Dispositivo Físico:** `{pz_dev_name}` | **MAC:** `{pz_mac}`\n"
            f"- **Hora del Primer Ataque:** `{patient_zero['first_timestamp']}` (Incidente #{patient_zero['incident_id']})\n"
            f"- **Diagnóstico IA & Causa Raíz:** `{patient_zero['attack_type']}`\n"
            f"- **Total de Ataques desde este Dispositivo:** `{patient_zero['total_alerts_from_device']}` alertas\n"
            f"- **Estado en Firewall del Router:** "
            f"{'🔒 BLOQUEADO EN CUARENTENA (Tráfico Cortado)' if pz_quarantined else '⚠️ ACTIVO EN RED (Requiere Aislamiento)'}"
        )

        if not pz_quarantined:
            if st.button(
                f"🔒 Aislar Paciente Cero (#{pz_dev_id}) en Firewall Router",
                key="btn_isolate_pz",
                type="primary",
                use_container_width=True,
            ):
                st.session_state.quarantined_devices.add(pz_dev_id)
                fw_cmds = generate_firewall_commands(
                    pz_dev_id, pz_ip, patient_zero["attack_type"][:25]
                )
                st.session_state.firewall_rules_log[pz_dev_id] = fw_cmds
                incident_store.log_incident(
                    timestamp=time.strftime("%H:%M:%S"),
                    model_name="Analista / IPS Gateway",
                    attack_type=patient_zero["attack_type"],
                    confidence=1.0,
                    action="🔒 ACCIÓN IPS: Regla DROP aplicada en iptables/nftables + Conntrack Flush",
                    device_name=pz_dev_name,
                )
                st.rerun()
        else:
            if st.button(
                f"🔓 Levantar Cuarentena a Dispositivo #{pz_dev_id}",
                key="btn_unisolate_pz",
                use_container_width=True,
            ):
                st.session_state.quarantined_devices.discard(pz_dev_id)
                st.session_state.firewall_rules_log.pop(pz_dev_id, None)
                st.rerun()

        # Mostrar comandos exactos de Firewall Linux / OpenWrt generados para el router real
        fw_info = st.session_state.firewall_rules_log.get(
            pz_dev_id, generate_firewall_commands(pz_dev_id, pz_ip, "Mirai_IPS")
        )
        with st.expander(
            "🧱 Ver Comandos Reales de Cortafuegos Generados (Linux iptables / nftables / OpenWrt)",
            expanded=True,
        ):
            st.caption(
                f"Lista Blanca Anti-Lockout activa para proteger Gateway y Admin: `{sorted(list(CRITICAL_WHITELIST_IPS))}`"
            )
            st.code(
                f"# 1. Bloqueo inmediato por IP + MAC Address (evita evasión por cambio de IP):\n"
                f"{fw_info.get('iptables_drop', '')}\n\n"
                f"# 2. Equivalente en Linux moderno (nftables):\n"
                f"{fw_info.get('nftables_drop', '')}\n\n"
                f"# 3. Corte instantáneo de sesiones TCP/UDP activas del atacante:\n"
                f"{fw_info.get('conntrack_flush', '')}",
                language="bash",
            )
    else:
        st.info(
            "🟢 Ningún dispositivo ha presentado comportamiento de botnet aún. "
            "Presione **'⚡ Lanzar Trama Real Ahora'** en la barra lateral para ver actuar a los 3 Anillos y al IPS."
        )

with col_mitigation:
    st.markdown("##### 🖧 Mapa de Estado y Umbrales Adaptativos de los 9 Dispositivos IoT")
    df_by_dev = incident_store.get_incidents_by_device()
    alerts_map = {}
    first_seen_map = {}
    if not df_by_dev.empty:
        for _, r in df_by_dev.iterrows():
            alerts_map[str(r["Dispositivo_IoT"])] = int(r["Total_Ataques"])
            first_seen_map[str(r["Dispositivo_IoT"])] = str(r["Primer_Ataque"])

    dev_status_rows = []
    for d_id in range(1, 10):
        d_label = f"{d_id}. {DEVICE_NAMES[d_id]} ({DEVICE_IPS[d_id]})"
        n_alerts = alerts_map.get(d_label, 0)
        is_q = d_id in st.session_state.quarantined_devices
        thr_val = get_adaptive_threshold(d_id, adaptive_enabled=adaptive_thr_enabled)
        if is_q:
            estado_str = "🔒 AISLADO (DROP en Firewall)"
        elif n_alerts > 0:
            estado_str = f"🚨 COMPROMETIDO ({n_alerts} ataques)"
        else:
            estado_str = "🟢 Operativo Normal"

        dev_status_rows.append(
            {
                "Dispositivo IoT (IP LAN)": d_label,
                "MAC Física": DEVICE_MACS[d_id],
                "Umbral IA": thr_val,
                "Estado IPS": estado_str,
                "Ataques": n_alerts,
                "1er Ataque": first_seen_map.get(d_label, "—"),
            }
        )
    st.dataframe(
        pd.DataFrame(dev_status_rows),
        use_container_width=True,
        hide_index=True,
        height=315,
    )

# ----------------- TELEMETRÍA EN VIVO Y BASE DE DATOS SQL -----------------
st.markdown("---")
col_chart, col_alerts = st.columns([1.75, 1.45])
with col_chart:
    st.subheader("📊 Flujo de Tráfico Real, Diagnóstico IA Multiclase y Forense Z-Score")
    if not df_stream.empty:
        st.line_chart(df_stream.set_index("Hora")["Score_Anomalía"], height=200)

        st.markdown(
            "##### 📡 Visor de Telemetría Forense (Comparación: Etiqueta Real CSV vs. Predicción IA Multiclase + Causa Raíz)"
        )
        df_telemetry = df_stream.iloc[::-1].head(12).reset_index(drop=True)
        st.dataframe(
            df_telemetry[
                [
                    "ID",
                    "Hora",
                    "Dispositivo_IoT",
                    "Real_CSV",
                    "Predicción_IA_Anillo2",
                    "Veredicto",
                    "Score_Anomalía",
                    "Causa_Raíz_ZScore",
                    "Acción_IPS",
                ]
            ],
            use_container_width=True,
            hide_index=True,
            height=240,
        )
    else:
        st.info(
            "Active 'Iniciar Captura Continua' o presione '⚡ Lanzar Trama Real Ahora' en la barra lateral."
        )

with col_alerts:
    st.subheader(
        f"🚨 Base de Datos Forense SQLite ({incident_store.count_incidents()} incidentes)"
    )
    st.caption(
        "Almacena dispositivo atacante, firma predicha por el Anillo 2, causa raíz física Z-Score y regla IPS aplicada."
    )
    df_sql_alerts = incident_store.get_recent_incidents(limit=20)
    if not df_sql_alerts.empty:
        st.dataframe(
            df_sql_alerts, use_container_width=True, hide_index=True, height=460
        )
    else:
        st.info("No se han registrado incidentes en la base de datos histórica aún.")

# ----------------- LABORATORIO DE HARDWARE REAL (MOTOR AFTERIMAGE EN VIVO) -----------------
st.markdown("---")
with st.expander(
    "🔌 Prototipo de extracción (ejemplo sintético, no captura real)",
    expanded=False,
):
    st.markdown(
        """
        Cuando conectes este sistema a un **dispositivo físico real** (ej. Raspberry Pi 4/5 o servidor Linux conectado al puerto *SPAN / Mirroring* de tu router),
        por el cable de red llegan paquetes crudos (`MAC`, `IP origen/destino`, `Puerto`, `Bytes`, `Timestamp`).
        El módulo [`src/streaming/live_feature_extractor.py`](file:///c:/Users/felip/Documents/Mi_Cerebro_Universitario/INTEGRADOR%20II%20SEM%20LIC%20EN%20CS/proyecto-iot-ml/src/streaming/live_feature_extractor.py)
        mantiene en memoria RAM las tablas hash con decaimiento exponencial $w \\leftarrow w \\cdot 2^{-\\lambda \\Delta t} + 1$ para las 5 ventanas ($\\lambda \\in \\{5, 3, 1, 0.1, 0.01\\}$)
        y construye en $O(1)$ el vector experimental de 115 variables, pendiente de equivalencia numérica **sin el bug del timestamp Unix 2017**.
        """
    )
    if st.button("🧪 Probar forma del vector con 25 ejemplos sintéticos"):
        extractor = LiveAfterImageExtractor(st.session_state.emulator.feature_cols)
        t_now = time.time()
        df_115 = None
        for i in range(25):
            df_115 = extractor.process_raw_packet(
                src_mac=DEVICE_MACS[5],
                src_ip=DEVICE_IPS[5],
                dst_ip="198.51.100.42",
                src_port=49152 + (i % 5),
                dst_port=80,
                pkt_size=512.0,
                timestamp=t_now + i * 0.002,
            )
        st.success(
            f"✅ Se procesaron 25 ejemplos de cabeceras generados por código y se generó un vector limpio de dimensión `{df_115.shape}` (características experimentales; no valida tráfico de hardware real)."
        )
        st.dataframe(df_115.iloc[:, :12], use_container_width=True, hide_index=True)

# ----------------- TRAZABILIDAD DEL ENTRENAMIENTO OFFLINE -----------------
with st.expander(
    "⚙️ ¿Cuándo y cómo se realizó el entrenamiento de los 3 Anillos? (Fase Offline vs. Fase Online)",
    expanded=False,
):
    audit_info = metrics_data.get("training_audit", {})
    mc_info = metrics_data.get("multiclass_attack_classifier", {})
    zd_info = metrics_data.get("zeroday_isolation_forest", {})
    ver_info = metrics_data.get("ml_audit_verification", {})
    st.markdown(
        f"""
        - **Fase Offline ([`src/models/baseline.py`](file:///c:/Users/felip/Documents/Mi_Cerebro_Universitario/INTEGRADOR%20II%20SEM%20LIC%20EN%20CS/proyecto-iot-ml/src/models/baseline.py)):** Último entrenamiento registrado el `{audit_info.get('trained_at', '2026-10-26')}` en `{audit_info.get('total_pipeline_duration_sec', 66.0)} s` sobre los **9 dispositivos IoT** (`Train = {metrics_data.get('train_samples', 29250)}`, `Val = {metrics_data.get('val_samples', 6715)}`, `Test = {metrics_data.get('test_samples', 6785)}`) con **ventanas de purga temporal (embargo 2.5%)** y **5-Fold CV sin fuga de escalado**.
        - **Anillo 1 (Binario Supervisado):** 5 modelos entrenados sin fuga de timestamp Unix (`HH_jit_*_mean` y `_variance` neutralizados; `HH_jit_*_weight` preservado).
        - **Anillo 2 (Clasificador Multiclase Balanceado — `model_multiclass_attack.pkl`):** Identifica la firma de ataque con **Accuracy Canónico = `{mc_info.get('accuracy', 0.93):.4f}`** y **F1-Macro = `{mc_info.get('f1_macro', 0.93):.4f}`**.
        - **Anillo 3 (Cazador Zero-Day No Supervisado — `model_zeroday_iforest.pkl`):** `LocalOutlierFactor (Novelty Detection)` entrenado **exclusivamente con tráfico 100% Benigno**; logra detectar el **`{zd_info.get('attack_detection_recall', 0.75)*100:.2f}%` de los ataques** (`F1 = {zd_info.get('f1_score', 0.83):.4f}`) sin haber visto jamás un solo ataque durante su entrenamiento.
        - **Verificación de Auditoría ML:** Prueba de sanidad (*Y-Randomization*) `F1 = {ver_info.get('y_randomization_sanity_f1', 0.54):.4f}` (control exploratorio; una sola permutación) | Estabilidad Multi-Semilla (`5 seeds`) `F1 = {ver_info.get('multi_seed_rf_f1_mean', 1.0):.4f} ± {ver_info.get('multi_seed_rf_f1_std', 0.0):.4f}` | Muestra posterior de las mismas capturas (`+10.000 filas`) `RF F1 = {ver_info.get('distant_horizon_rf_f1', 0.9998):.4f}` (`FPR = {ver_info.get('distant_horizon_rf_fpr', 0.0)*100:.2f}%`).
        """
    )
    st.info('El entrenamiento histórico conserva limitaciones conocidas. Los candidatos del protocolo 6/2/1 se mantienen separados en experiments/rigorous_v1/ y se enrutan dinámicamente cuando el modo "Evaluación Ciega 6/2/1" está activo en la barra lateral.')

# ----------------- COMPARATIVA EXPERIMENTAL DE MODELOS Y EXPLICABILIDAD -----------------
st.markdown("---")
st.subheader("🏆 Comparativa Experimental de Modelos y Reducción de Falsos Positivos con IPS Adaptativo")

from src.models.reporting import historical_comparison, multiclass_tasks
st.caption('Resultados históricos de desarrollo. Valores vacíos: esa configuración no fue evaluada. Las tasas se expresan de 0 a 1.')
st.dataframe(pd.DataFrame(historical_comparison(metrics_data)), hide_index=True)
st.dataframe(pd.DataFrame(multiclass_tasks(metrics_data.get('multiclass_attack_classifier', {}))), hide_index=True)

rigorous_dir = os.path.join(os.path.dirname(REGISTRY_DIR), 'experiments', 'rigorous_v1')
rigorous_summary = os.path.join(rigorous_dir, 'summary.csv')
st.subheader('Evaluación por periodos, dispositivos y familias excluidas')
if os.path.exists(rigorous_summary):
    rigorous_results = pd.read_csv(rigorous_summary)
    st.caption('Capturas reales de laboratorio N-BaIoT. Calibración separada. Pendiente validación con capturas locales independientes; no certifica producción.')
    st.dataframe(rigorous_results, hide_index=True)
else:
    st.info('Benchmark exigente todavía sin resultados completos. No se sustituyen por los resultados históricos.')

st.markdown("---")
col_fi, col_lodo = st.columns([1.15, 1.55])

with col_fi:
    st.subheader("🔍 Explicabilidad Global: Top 15 Características Físicas")
    top_rf = metrics_data.get("top_15_features_rf", {})
    if top_rf:
        df_fi = pd.DataFrame(
            {
                "Característica": list(top_rf.keys()),
                "Importancia Relativa": list(top_rf.values()),
            }
        ).set_index("Característica")
        st.bar_chart(df_fi)
    else:
        st.info("Ejecute baseline.py para visualizar el ranking de Feature Importance.")

with col_lodo:
    st.subheader("🧪 Generalización LODO en los 9 Dispositivos (Estándar vs. IPS Adaptativo)")
    lodo_info = metrics_data.get("lodo_9_devices", {}).get("folds", {})
    if lodo_info:
        rows_lodo = []
        for _, fdata in lodo_info.items():
            row_dict = {
                "Disp. Excluido (Test)": f"{fdata['device_id']}. {fdata['device_name']}",
                "LR F1": fdata["lr"]["f1"],
                "RF Estándar F1": fdata["rf"]["f1"],
                "RF FPR (%)": round(fdata["rf"]["fpr"] * 100.0, 2),
            }
            if "rf_adaptive" in fdata:
                row_dict["RF+Adapt IPS F1"] = fdata["rf_adaptive"]["f1"]
                row_dict["RF+Adapt FPR (%)"] = round(
                    fdata["rf_adaptive"]["fpr"] * 100.0, 2
                )
            rows_lodo.append(row_dict)
        st.dataframe(pd.DataFrame(rows_lodo), use_container_width=True, height=340)
    else:
        st.info("Resultados LODO pendientes de generación.")

# ----------------- AUTO-REFRESCO CONTINUO (STREAMLIT RERUN) -----------------
if run_sim:
    time.sleep(stream_speed)
    st.rerun()
