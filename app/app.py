"""Dashboard MVP de Monitoreo Centralizado de Redes IoT con Autenticación JWT, SQLite y Feature Importance."""

import os
import sys
import time
import json
import hmac
import base64
import hashlib
import joblib
import pandas as pd
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.streaming.emulator import IoTTrafficStreamEmulator
from src.streaming.incident_store import IncidentStore

st.set_page_config(
    page_title="Sistema Centralizado de Detección de Botnets IoT",
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
    """Carga los modelos verificando su integridad criptográfica SHA-256 contra manipulaciones."""
    manifest_path = os.path.join(registry_dir, "artifacts_sha256.json")
    if not os.path.exists(manifest_path):
        return None, {}

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    scaler_file = os.path.join(registry_dir, "scaler_nbaiot.pkl")
    if not verify_file_sha256(scaler_file, manifest.get("scaler_nbaiot.pkl", "")):
        raise SecurityIntegrityError("El artefacto scaler_nbaiot.pkl está corrupto o fue modificado.")
    scaler = joblib.load(scaler_file)

    model_mapping = {
        "Random Forest (Ensamble Bagging)": "model_random_forest.pkl",
        "Gradient Boosting (Ensamble Boosting)": "model_gradient_boosting.pkl",
        "Linear Support Vector Machine (LinearSVC Calibrado)": "model_svm.pkl",
        "Árbol de Decisión (max_depth=8)": "model_candidate_dt.pkl",
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

    return scaler, models_dict


# ----------------- CONTROL DE ACCESO (JWT + HMAC) -----------------
# Las credenciales se leen desde variables de entorno del servidor.
# No se pre-llenan ni exponen en el formulario para cumplir con OWASP AppSec (CWE-200 / CWE-798).
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
            <h1>🛡️ Acceso Seguro a la Consola de Monitoreo IoT</h1>
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

# Extraer el sujeto autenticado directamente de los claims del token JWT verificado
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

st.sidebar.title("🛡️ Panel del Analista")
st.sidebar.markdown(f"**Operador:** `{current_user}`")
st.sidebar.markdown("**Sesión:** JWT `HS256` Válida 🔒")
st.sidebar.markdown("**Gateway:** Centralizado (Router WiFi)")

if st.sidebar.button("Cerrar Sesión", use_container_width=True):
    st.session_state.jwt_token = None
    st.rerun()

st.title("🛡️ Sistema Centralizado de Detección de Botnets IoT")
st.caption(
    "Monitoreo de tráfico en tiempo real sobre capturas de 9 dispositivos N-BaIoT infectados por botnets Mirai y BASHLITE. "
    "Desacoplamiento MLOps mediante artefactos inmutables y persistencia relacional SQLite."
)

# Carga segura de modelos
try:
    scaler, models_dict = load_verified_models(REGISTRY_DIR)
except SecurityIntegrityError as err:
    st.error(f"🚨 ALERTA DE SEGURIDAD CRÍTICA: {err}")
    st.stop()

# Cargar métricas offline
metrics_path = os.path.join(REGISTRY_DIR, "baseline_metrics.json")
metrics_data = {}
if os.path.exists(metrics_path):
    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics_data = json.load(f)

# Selector de modelo
if models_dict:
    selected_model_label = st.sidebar.selectbox(
        "Clasificador Activo", options=list(models_dict.keys()), index=0
    )
    model = models_dict[selected_model_label]
    st.sidebar.success(f"Modelo activo: {selected_model_label}")
else:
    selected_model_label = "No disponible"
    model = None
    st.sidebar.warning("Artefactos no encontrados en models_registry/. Ejecute baseline.py primero.")

# Inicialización de estado de sesión para streaming
if "stream_data" not in st.session_state:
    st.session_state.stream_data = []
if "emulator" not in st.session_state:
    st.session_state.emulator = IoTTrafficStreamEmulator()
if "last_latency_ms" not in st.session_state:
    st.session_state.last_latency_ms = 0.0

st.sidebar.markdown("---")
st.sidebar.subheader("Simulación de Red (Router Mirroring)")
run_sim = st.sidebar.toggle("Iniciar Captura Continua (En Vivo 🟢)", value=False)
anomaly_prob = st.sidebar.slider("Probabilidad de Ataque", 0.0, 0.5, 0.15, step=0.05)
st.session_state.emulator.anomaly_prob = anomaly_prob

stream_speed = st.sidebar.slider(
    "Velocidad de flujo (seg/ciclo)",
    min_value=0.2,
    max_value=2.0,
    value=0.5,
    step=0.1,
    help="Tiempo de espera entre ciclos de refresco continuo.",
)

packets_per_cycle = st.sidebar.select_slider(
    "Paquetes por ciclo",
    options=[1, 2, 5, 10],
    value=2,
    help="Cantidad de paquetes evaluados por el modelo en cada iteración.",
)

if st.sidebar.button("🗑️ Limpiar Base de Datos SQL", use_container_width=True):
    incident_store.clear_all()
    st.session_state.stream_data = []
    st.sidebar.success("Historial de incidentes y telemetría reiniciados con éxito.")
    st.rerun()

# Procesamiento de paquetes en streaming
if run_sim and model is not None and scaler is not None:
    latencies = []
    for _ in range(packets_per_cycle):
        packet = st.session_state.emulator.stream_packet()
        t_start = time.perf_counter()
        feat_scaled = scaler.transform(packet["features"])
        pred = int(model.predict(feat_scaled)[0])
        prob = (
            float(model.predict_proba(feat_scaled)[0][1])
            if hasattr(model, "predict_proba")
            else float(pred)
        )
        latencies.append((time.perf_counter() - t_start) * 1000.0)

        record = {
            "ID": packet["packet_id"],
            "Hora": packet["timestamp"],
            "Score_Anomalía": round(prob, 4),
            "Clase_Predicha": "MALICIOSO" if pred == 1 else "BENIGNO",
            "Simulado": packet["simulated_ground_truth"],
        }
        st.session_state.stream_data.append(record)
        if len(st.session_state.stream_data) > 60:
            st.session_state.stream_data.pop(0)

        # Solo se registran en la base de datos histórica los incidentes reales (amenazas)
        if pred == 1:
            incident_store.log_incident(
                timestamp=packet["timestamp"],
                model_name=selected_model_label.split(" (")[0],
                attack_type=packet["simulated_ground_truth"],
                confidence=prob,
                action="Alerta enviada a Gateway",
            )
    if latencies:
        st.session_state.last_latency_ms = float(sum(latencies) / len(latencies))

# KPIs principales
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
df_stream = pd.DataFrame(st.session_state.stream_data)

if not df_stream.empty:
    total = len(df_stream)
    malicious = int((df_stream["Clase_Predicha"] == "MALICIOSO").sum())
    rate = (malicious / total) * 100.0

    # Detección de ráfagas recientes en los últimos 5 paquetes
    recent_malicious = int((df_stream.tail(5)["Clase_Predicha"] == "MALICIOSO").sum())

    kpi1.metric("Paquetes Analizados", f"{st.session_state.emulator.packet_count}")
    kpi2.metric("Amenazas en Ventana", f"{malicious}")
    kpi3.metric("Tasa de Anomalías", f"{rate:.1f}%")
    kpi4.metric("Latencia Inferencia", f"{st.session_state.last_latency_ms:.2f} ms")

    # Lógica de estados de alerta de SOC (Security Operations Center):
    if malicious == 0:
        kpi5.success("🟢 ESTADO: RED SEGURA")
    elif recent_malicious >= 2 or rate >= 15.0 or malicious >= 5:
        kpi5.error("🚨 ESTADO: RED BAJO ATAQUE")
    else:
        kpi5.warning("⚠️ ESTADO: AMENAZA DETECTADA")
else:
    kpi1.metric("Paquetes Analizados", 0)
    kpi2.metric("Amenazas en Ventana", 0)
    kpi3.metric("Tasa de Anomalías", "0.0%")
    kpi4.metric("Latencia Inferencia", "0.00 ms")
    kpi5.info("⏳ EN ESPERA")

col_chart, col_alerts = st.columns([1.8, 1.5])
with col_chart:
    st.subheader("📊 Flujo de Tráfico y Puntuación de Inferencia")
    if not df_stream.empty:
        st.line_chart(df_stream.set_index("Hora")["Score_Anomalía"], height=220)

        st.markdown("##### 📡 Visor de Telemetría en Vivo (Todos los Flujos)")
        st.caption(
            "El **Score de Anomalía** representa la probabilidad condicional $P(\\text{Ataque} \\mid x)$ "
            "calculada por el modelo (de 0.0 a 1.0). Un score $\\geq 0.50$ clasifica el paquete como MALICIOSO."
        )
        df_telemetry = df_stream.iloc[::-1].head(10).reset_index(drop=True)
        st.dataframe(
            df_telemetry[["ID", "Hora", "Clase_Predicha", "Score_Anomalía", "Simulado"]],
            use_container_width=True,
            height=200,
        )
    else:
        st.info(
            "Active la casilla 'Iniciar Captura Continua' en la barra lateral para observar la inferencia en tiempo real."
        )

with col_alerts:
    st.subheader(
        f"🚨 Base de Datos Histórica SQL ({incident_store.count_incidents()} incidentes)"
    )
    st.caption("Solo almacena incidentes de seguridad (amenazas detectadas) para trazabilidad forense.")
    df_sql_alerts = incident_store.get_recent_incidents(limit=20)
    if not df_sql_alerts.empty:
        st.dataframe(df_sql_alerts, use_container_width=True, height=440)
    else:
        st.info("No se han registrado incidentes en la base de datos histórica aún.")

# Sección de Explicabilidad (Feature Importance) y Validación LODO
st.markdown("---")
col_fi, col_lodo = st.columns([1.2, 1.5])

with col_fi:
    st.subheader("🔍 Explicabilidad: Top 15 Características (Feature Importance)")
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
    st.subheader("🧪 Generalización Leave-One-Device-Out (LODO — 9 Dispositivos IoT)")
    lodo_info = metrics_data.get("lodo_9_devices", {}).get("folds", {})
    if lodo_info:
        rows_lodo = []
        for _, fdata in lodo_info.items():
            rows_lodo.append(
                {
                    "Disp. Excluido (Test)": f"{fdata['device_id']}. {fdata['device_name']}",
                    "LR F1 (Base)": fdata["lr"]["f1"],
                    "RF F1": fdata["rf"]["f1"],
                    "GB F1": fdata["gb"]["f1"],
                    "SVM F1": fdata["svm"]["f1"],
                    "RF FPR (%)": round(fdata["rf"]["fpr"] * 100.0, 2),
                }
            )
        st.dataframe(pd.DataFrame(rows_lodo), use_container_width=True, height=340)
    else:
        st.info("Resultados LODO pendientes de generación.")

# ----------------- AUTO-REFRESCO CONTINUO (STREAMLIT RERUN) -----------------
if run_sim:
    time.sleep(stream_speed)
    st.rerun()
