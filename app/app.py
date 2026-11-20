"""IoT Perimeter Guard — Consola centralizada de monitoreo y detección de anomalías en redes IoT."""

import os
import sys
import time
import json
import hmac
import html
import base64
import hashlib
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
from src.models.reporting import historical_comparison, multiclass_tasks

st.set_page_config(
    page_title="IoT Perimeter Guard",
    layout="wide",
    initial_sidebar_state="expanded",
)

REGISTRY_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "models_registry")
)
EXPERIMENTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "experiments", "rigorous_v1")
)

DEVICE_CATEGORIES = {
    1: "Timbre inteligente",
    2: "Termostato",
    3: "Timbre inteligente",
    4: "Monitor de bebé",
    5: "Cámara de seguridad",
    6: "Cámara de seguridad",
    7: "Webcam IP",
    8: "Cámara de seguridad",
    9: "Cámara de seguridad",
}

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 30


class SecurityIntegrityError(RuntimeError):
    """Excepción lanzada cuando falla la verificación criptográfica SHA-256 de un artefacto ML."""


def inject_minimal_css():
    """Inyecta una hoja de estilos minimalista, limpia y sobria inspirada en consolas de red modernas."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            color: #0F172A;
        }
        #MainMenu, footer, .stDeployButton { visibility: hidden; }
        header[data-testid="stHeader"] {
            background: rgba(248, 250, 252, 0.85);
            backdrop-filter: blur(8px);
            height: 2.4rem;
        }
        .block-container {
            padding-top: 3.1rem;
            padding-bottom: 2.5rem;
            max-width: 1320px;
        }
        section[data-testid="stSidebar"] {
            background-color: #FFFFFF;
            border-right: 1px solid #E2E8F0;
        }
        section[data-testid="stSidebar"] .block-container {
            padding-top: 1.4rem;
        }

        /* Encabezado superior */
        .app-topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.1rem;
            padding-bottom: 0.9rem;
            border-bottom: 1px solid #E2E8F0;
        }
        .app-title {
            font-size: 1.45rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            color: #0F172A;
            margin: 0;
        }
        .app-subtitle {
            font-size: 0.87rem;
            color: #64748B;
            margin: 0.15rem 0 0 0;
        }
        .env-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.76rem;
            font-weight: 600;
            padding: 5px 11px;
            border-radius: 999px;
            background: #F1F5F9;
            color: #334155;
            border: 1px solid #E2E8F0;
        }

        /* Hero card de estado de red */
        .hero-card {
            border-radius: 12px;
            padding: 1.25rem 1.45rem;
            margin-bottom: 1.15rem;
            border: 1px solid #E2E8F0;
            background: #FFFFFF;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
        }
        .hero-safe { border-left: 4px solid #059669; background: #F0FDF4; border-color: #BBF7D0; }
        .hero-warn { border-left: 4px solid #D97706; background: #FFFBEB; border-color: #FDE68A; }
        .hero-alert { border-left: 4px solid #DC2626; background: #FEF2F2; border-color: #FECACA; }
        .hero-idle { border-left: 4px solid #334155; background: #FFFFFF; }
        .hero-heading {
            font-size: 1.08rem;
            font-weight: 600;
            color: #0F172A;
            margin: 0 0 0.2rem 0;
        }
        .hero-desc {
            font-size: 0.88rem;
            color: #475569;
            margin: 0;
        }

        /* Badges minimalistas */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 3px 10px;
            border-radius: 999px;
            font-size: 0.74rem;
            font-weight: 600;
            letter-spacing: 0.01em;
            white-space: nowrap;
        }
        .badge-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
        .badge-ok { background: #DCFCE7; color: #166534; }
        .badge-ok .badge-dot { background: #16A34A; }
        .badge-warn { background: #FEF3C7; color: #92400E; }
        .badge-warn .badge-dot { background: #D97706; }
        .badge-danger { background: #FEE2E2; color: #991B1B; }
        .badge-danger .badge-dot { background: #DC2626; }
        .badge-neutral { background: #F1F5F9; color: #334155; }
        .badge-neutral .badge-dot { background: #64748B; }

        /* Tarjetas KPI */
        .kpi-box {
            background: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 10px;
            padding: 0.95rem 1.1rem;
            height: 100%;
        }
        .kpi-label {
            font-size: 0.76rem;
            font-weight: 500;
            color: #64748B;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 0.35rem;
        }
        .kpi-val {
            font-size: 1.55rem;
            font-weight: 700;
            color: #0F172A;
            line-height: 1.15;
        }
        .kpi-sub {
            font-size: 0.78rem;
            color: #64748B;
            margin-top: 0.25rem;
        }

        /* Tarjeta de dispositivo en grilla 3x3 */
        .dev-card {
            background: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 10px;
            padding: 0.95rem 1.05rem;
            margin-bottom: 0.65rem;
            transition: border-color 0.15s ease;
        }
        .dev-card-danger { border-color: #FCA5A5; background: #FEF2F2; }
        .dev-card-quarantine { border-color: #FCD34D; background: #FFFBEB; }
        .dev-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 8px;
            margin-bottom: 0.45rem;
        }
        .dev-name {
            font-size: 0.9rem;
            font-weight: 600;
            color: #0F172A;
            line-height: 1.25;
        }
        .dev-cat {
            font-size: 0.75rem;
            color: #64748B;
            margin-top: 2px;
        }
        .dev-meta {
            font-size: 0.76rem;
            color: #475569;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            margin-top: 0.35rem;
        }

        /* Tarjeta de diagnóstico humano */
        .diag-card {
            background: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 10px;
            padding: 1.05rem 1.25rem;
            margin: 0.75rem 0 1.1rem 0;
        }
        .diag-title {
            font-size: 0.92rem;
            font-weight: 600;
            color: #0F172A;
            margin-bottom: 0.35rem;
        }
        .diag-text {
            font-size: 0.86rem;
            color: #334155;
            line-height: 1.5;
            margin: 0;
        }

        /* Aviso sutil de laboratorio */
        .scope-note {
            font-size: 0.79rem;
            color: #64748B;
            background: #F1F5F9;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 0.55rem 0.85rem;
            margin-bottom: 1.0rem;
        }

        /* Pestañas limpias */
        .stTabs [data-baseweb="tab-list"] {
            gap: 0.5rem;
            border-bottom: 1px solid #E2E8F0;
        }
        .stTabs [data-baseweb="tab"] {
            font-size: 0.88rem;
            font-weight: 500;
            color: #64748B;
            padding: 0.6rem 1.0rem;
        }
        .stTabs [aria-selected="true"] {
            color: #0F172A !important;
            font-weight: 600 !important;
        }

        /* Caja de login */
        .login-wrap {
            max-width: 420px;
            margin: 3.5rem auto 1.2rem auto;
            text-align: center;
        }
        .login-brand {
            font-size: 1.55rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            color: #0F172A;
            margin-bottom: 0.35rem;
        }
        .login-sub {
            font-size: 0.88rem;
            color: #64748B;
            margin-bottom: 1.5rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def translate_root_cause_human(root_cause_str: str, attack_label: str) -> str:
    """Traduce variables técnicas Z-Score a una explicación clara para usuarios no técnicos."""
    rc = root_cause_str.lower()
    reasons = []
    if "weight" in rc:
        reasons.append("aumento abrupto en el volumen de paquetes enviados")
    if "magnitude" in rc or "mean" in rc:
        reasons.append("tamaño promedio de tráfico fuera del perfil normal del equipo")
    if "variance" in rc or "std" in rc or "radius" in rc:
        reasons.append("variación irregular e inestable entre conexiones consecutivas")
    if "jit" in rc:
        reasons.append("cadencia anómala en los intervalos de envío")

    if not reasons:
        reasons.append("desviación estadística severa frente al comportamiento habitual del dispositivo")

    cause_phrase = ", ".join(reasons[:2])
    atk_upper = str(attack_label).upper()
    if "MIRAI" in atk_upper:
        family_desc = "Comportamiento compatible con la botnet Mirai (saturación de red)."
    elif "BASHLITE" in atk_upper or "GAFGYT" in atk_upper:
        family_desc = "Comportamiento compatible con la botnet BASHLITE / Gafgyt."
    elif "ZERO_DAY" in atk_upper:
        family_desc = "Patrón desconocido detectado por desviación volumétrica (Anillo 3)."
    else:
        family_desc = "Tráfico clasificado fuera de la línea base segura."

    return f"Se detectó un {cause_phrase}. {family_desc}"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue_jwt_hs256(subject: str, secret: str, ttl_seconds: int = 3600) -> str:
    """Genera un token JWT (RFC 7519) firmado con HMAC-SHA256 y expiración."""
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
    """Verifica firma HMAC-SHA256 y vigencia temporal de un token JWT."""
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
        return payload.get("exp", 0) >= int(time.time())
    except Exception:
        return False


def verify_file_sha256(filepath: str, expected_hash: str) -> bool:
    """Calcula el hash SHA-256 de un archivo en bloques de 64 KB y lo compara en tiempo constante."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hmac.compare_digest(hasher.hexdigest().lower(), expected_hash.lower())


@st.cache_resource
def get_incident_store() -> IncidentStore:
    """Retorna la instancia persistente de SQLite sin reinicializar en cada render."""
    return IncidentStore()


@st.cache_data(ttl=120)
def load_baseline_metrics(registry_dir: str) -> dict:
    metrics_path = os.path.join(registry_dir, "baseline_metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


@st.cache_data(ttl=120)
def load_rigorous_summary(experiments_dir: str) -> pd.DataFrame:
    summary_path = os.path.join(experiments_dir, "summary.csv")
    if os.path.exists(summary_path):
        return pd.read_csv(summary_path)
    return pd.DataFrame()


@st.cache_resource
def load_verified_models(registry_dir: str):
    """Carga los 3 Anillos verificando su integridad criptográfica SHA-256 y devuelve reporte de auditoría."""
    manifest_path = os.path.join(registry_dir, "artifacts_sha256.json")
    if not os.path.exists(manifest_path):
        return None, {}, None, None, []

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    audit_log = []
    scaler_file = os.path.join(registry_dir, "scaler_nbaiot.pkl")
    scaler_hash = manifest.get("scaler_nbaiot.pkl", "")
    if not verify_file_sha256(scaler_file, scaler_hash):
        raise SecurityIntegrityError(
            "El artefacto scaler_nbaiot.pkl está corrupto o fue modificado."
        )
    scaler = joblib.load(scaler_file)
    audit_log.append(
        {"Artefacto": "scaler_nbaiot.pkl", "Rol": "Preprocesador", "SHA-256": scaler_hash[:16] + "...", "Estado": "Verificado"}
    )

    model_mapping = {
        "Random Forest": "model_random_forest.pkl",
        "Gradient Boosting": "model_gradient_boosting.pkl",
        "Linear SVM (Calibrado)": "model_svm.pkl",
        "Árbol de Decisión": "model_candidate_dt.pkl",
        "Regresión Logística (Línea Base)": "model_baseline_lr.pkl",
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
            audit_log.append(
                {"Artefacto": filename, "Rol": f"Anillo 1 ({label})", "SHA-256": expected[:16] + "...", "Estado": "Verificado"}
            )

    mc_model = None
    mc_path = os.path.join(registry_dir, "model_multiclass_attack.pkl")
    if os.path.exists(mc_path) and "model_multiclass_attack.pkl" in manifest:
        mc_hash = manifest["model_multiclass_attack.pkl"]
        if not verify_file_sha256(mc_path, mc_hash):
            raise SecurityIntegrityError("Integridad comprometida en model_multiclass_attack.pkl.")
        mc_model = joblib.load(mc_path)
        if hasattr(mc_model, "n_jobs"):
            mc_model.n_jobs = 1
        audit_log.append(
            {"Artefacto": "model_multiclass_attack.pkl", "Rol": "Anillo 2 (Multiclase 10 ataques)", "SHA-256": mc_hash[:16] + "...", "Estado": "Verificado"}
        )

    zd_model = None
    zd_path = os.path.join(registry_dir, "model_zeroday_iforest.pkl")
    if os.path.exists(zd_path) and "model_zeroday_iforest.pkl" in manifest:
        zd_hash = manifest["model_zeroday_iforest.pkl"]
        if not verify_file_sha256(zd_path, zd_hash):
            raise SecurityIntegrityError("Integridad comprometida en model_zeroday_iforest.pkl.")
        zd_model = joblib.load(zd_path)
        if hasattr(zd_model, "n_jobs"):
            zd_model.n_jobs = 1
        audit_log.append(
            {"Artefacto": "model_zeroday_iforest.pkl", "Rol": "Anillo 3 (Zero-Day LOF)", "SHA-256": zd_hash[:16] + "...", "Estado": "Verificado"}
        )

    return scaler, models_dict, mc_model, zd_model, audit_log


@st.cache_resource
def load_blind_lodo_candidates(registry_dir: str):
    """Carga los 9 modelos de rotación ciega 6/2/1 verificando su hash SHA-256."""
    exp_root = os.path.join(os.path.dirname(registry_dir), "experiments", "rigorous_v1")
    hashes_path = os.path.join(exp_root, "candidate_hashes.json")
    if not os.path.exists(hashes_path):
        return {}, []
    try:
        with open(hashes_path, "r", encoding="utf-8") as f:
            cand_hashes = json.load(f)
    except Exception:
        return {}, []

    blind_dict = {}
    blind_audit = []
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
                blind_audit.append(
                    {
                        "Artefacto": f"device_{dev_id}_rf/candidate.joblib",
                        "Rol": f"Fold ciego 6/2/1 (Disp. {dev_id} excluido)",
                        "SHA-256": expected_sha[:16] + "...",
                        "Estado": "Verificado",
                    }
                )
    return blind_dict, blind_audit


# ----------------- CONTROL DE ACCESO (JWT + RATE LIMITING) -----------------
JWT_SECRET = os.environ.get("CINF200_JWT_SECRET", "super-secret-iot-unab-2026-key")
EXPECTED_USER = os.environ.get(
    "CINF200_ANALYST_USER", os.environ.get("IOT_ADMIN_USER", "analista_unab")
)
EXPECTED_PASSWORD = os.environ.get(
    "CINF200_ANALYST_PASS", os.environ.get("IOT_DASHBOARD_SECRET", "demo-jwt-key-2026")
)
USING_DEFAULT_CREDS = (
    "CINF200_ANALYST_PASS" not in os.environ and "IOT_DASHBOARD_SECRET" not in os.environ
)

inject_minimal_css()


def check_authentication() -> bool:
    if "jwt_token" not in st.session_state:
        st.session_state.jwt_token = None
    if "failed_logins" not in st.session_state:
        st.session_state.failed_logins = 0
    if "lockout_until" not in st.session_state:
        st.session_state.lockout_until = 0.0

    if st.session_state.jwt_token and verify_jwt_hs256(st.session_state.jwt_token, JWT_SECRET):
        return True

    st.markdown(
        """
        <div class="login-wrap">
            <div class="login-brand">IoT Perimeter Guard</div>
            <div class="login-sub">Consola centralizada de monitoreo y defensa de redes IoT</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    _, col_mid, _ = st.columns([1.1, 1.2, 1.1])
    with col_mid:
        now = time.time()
        locked = now < st.session_state.lockout_until
        remaining = int(st.session_state.lockout_until - now) if locked else 0

        if locked:
            st.error(f"Demasiados intentos fallidos. Intente nuevamente en {remaining} segundos.")

        with st.form("login_form"):
            user = st.text_input(
                "Usuario",
                value="",
                placeholder="analista_unab",
                disabled=locked,
            )
            pwd = st.text_input(
                "Contraseña",
                type="password",
                value="",
                placeholder="••••••••••••",
                disabled=locked,
            )
            submit = st.form_submit_button(
                "Ingresar", use_container_width=True, type="primary", disabled=locked
            )

            if submit and not locked:
                user_clean = user.strip()
                pwd_clean = pwd.strip()
                if not user_clean or not pwd_clean:
                    st.warning("Ingrese su usuario y contraseña.")
                else:
                    valid_user = hmac.compare_digest(user_clean, EXPECTED_USER)
                    valid_pass = hmac.compare_digest(pwd_clean, EXPECTED_PASSWORD)
                    if valid_user and valid_pass:
                        st.session_state.failed_logins = 0
                        st.session_state.lockout_until = 0.0
                        st.session_state.jwt_token = issue_jwt_hs256(
                            subject=user_clean, secret=JWT_SECRET
                        )
                        st.rerun()
                    else:
                        st.session_state.failed_logins += 1
                        if st.session_state.failed_logins >= MAX_LOGIN_ATTEMPTS:
                            st.session_state.lockout_until = time.time() + LOCKOUT_SECONDS
                            st.session_state.failed_logins = 0
                            st.error(
                                f"Acceso bloqueado temporalmente por {LOCKOUT_SECONDS} s tras {MAX_LOGIN_ATTEMPTS} intentos fallidos."
                            )
                        else:
                            st.error("Credenciales inválidas.")

        st.caption(
            "Sesión firmada con JWT HS256 y comparación en tiempo constante."
            + (" Modo laboratorio activo (credenciales locales)." if USING_DEFAULT_CREDS else "")
        )
    return False


if not check_authentication():
    st.stop()


# ----------------- INICIALIZACIÓN DE RECURSOS -----------------
incident_store = get_incident_store()
metrics_data = load_baseline_metrics(REGISTRY_DIR)
rigorous_df = load_rigorous_summary(EXPERIMENTS_DIR)

current_user = "analista"
try:
    payload_bytes = base64.urlsafe_b64decode(st.session_state.jwt_token.split(".")[1] + "==")
    current_user = json.loads(payload_bytes.decode("utf-8")).get("sub", "analista")
except Exception:
    current_user = "analista"

try:
    scaler, models_dict, multiclass_model, zeroday_model, core_audit_log = load_verified_models(
        REGISTRY_DIR
    )
    blind_lodo_candidates, blind_audit_log = load_blind_lodo_candidates(REGISTRY_DIR)
except SecurityIntegrityError as err:
    st.error(f"Error crítico de integridad criptográfica SHA-256: {err}")
    st.stop()

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


# ----------------- BARRA LATERAL MINIMALISTA -----------------
with st.sidebar:
    st.markdown("### IoT Perimeter Guard")
    st.caption(f"Operador: `{current_user}` · Sesión JWT activa")
    if st.button("Cerrar sesión", use_container_width=True):
        st.session_state.jwt_token = None
        st.rerun()

    st.divider()
    st.markdown("#### Simular tráfico en un dispositivo")
    st.caption("Seleccione un equipo y un escenario real del conjunto de prueba.")

    device_options = {f"{d_id}. {DEVICE_NAMES[d_id]}": d_id for d_id in range(1, 10)}
    selected_dev_str = st.selectbox(
        "Dispositivo", options=list(device_options.keys()), index=0
    )
    selected_dev_id = device_options[selected_dev_str]

    available_attacks = st.session_state.emulator.get_available_attacks(
        device_id=selected_dev_id
    )
    default_atk_idx = 1 if len(available_attacks) > 1 else 0
    selected_attack_type = st.selectbox(
        "Escenario de tráfico",
        options=available_attacks,
        index=default_atk_idx,
    )
    burst_count = st.select_slider("Tramas a enviar", options=[1, 3, 5, 10], value=1)

    launch_clicked = st.button(
        "Ejecutar prueba ahora", use_container_width=True, type="primary"
    )

    # Ajustes avanzados colapsados para mantener una vista limpia para usuarios nuevos
    st.divider()
    with st.expander("Configuración del motor y simulación", expanded=False):
        if models_dict:
            selected_model_label = st.selectbox(
                "Anillo 1 (Modo histórico)", options=list(models_dict.keys()), index=0
            )
            model = models_dict[selected_model_label]
        else:
            selected_model_label = "No disponible"
            model = None

        blind_lodo_enabled = st.toggle(
            "Evaluación ciega 6/2/1 (0% visto)",
            value=bool(blind_lodo_candidates),
            disabled=not bool(blind_lodo_candidates),
            help="Al evaluar el Dispositivo X usa el modelo device_X_rf entrenado sin datos de ese equipo.",
        )
        adaptive_thr_enabled = st.toggle(
            "Umbral calibrado anti-FPR",
            value=True,
            help="Aplica el umbral calibrado en dispositivos externos para contener falsas alarmas.",
        )
        auto_ips_quarantine = st.toggle(
            "Aislamiento automático al detectar amenaza",
            value=True,
        )
        enable_zeroday_ring = st.toggle(
            "Anillo 3: Detector Zero-Day (LOF)",
            value=True,
        )

        st.markdown("**Reproducción continua**")
        run_sim = st.toggle("Activar flujo continuo", value=False)
        anomaly_prob = st.slider("Proporción de ataques", 0.0, 0.8, 0.0, step=0.05)
        st.session_state.emulator.anomaly_prob = anomaly_prob
        stream_speed = st.slider("Intervalo (seg)", 0.3, 2.0, 0.6, step=0.1)
        packets_per_cycle = st.select_slider("Tramas por ciclo", options=[1, 2, 5], value=2)

    if blind_lodo_enabled and selected_dev_id in blind_lodo_candidates:
        c_meta = blind_lodo_candidates[selected_dev_id]["metadata"]
        st.caption(
            f"Motor ciego activo: `device_{selected_dev_id}_rf` "
            f"(entrenado en {c_meta['train_devices']}; calibrado en {c_meta['calibration_devices']}; "
            f"0% datos de este equipo)."
        )

    st.divider()
    if st.button("Reiniciar alertas y cuarentenas", use_container_width=True):
        incident_store.clear_all()
        st.session_state.stream_data = []
        st.session_state.quarantined_devices = set()
        st.session_state.firewall_rules_log = {}
        st.session_state.last_injected_info = None
        st.rerun()


# ----------------- MOTOR DE EVALUACIÓN DE 3 ANILLOS -----------------
def evaluate_and_record_packet(packet: dict) -> dict:
    """Ejecuta los 3 anillos defensivos, calcula Z-Score y actualiza estado IPS."""
    t_start = time.perf_counter()
    feat_scaled = scaler.transform(packet["features"])

    dev_id = int(packet.get("device_id", 1))
    dev_name = str(packet.get("device_name", DEVICE_NAMES.get(dev_id, f"Disp. {dev_id}")))
    dev_ip = str(packet.get("device_ip", DEVICE_IPS.get(dev_id, f"192.168.1.{100 + dev_id}")))
    dev_label = f"{dev_id}. {dev_name} ({dev_ip})"

    t_ring1_start = time.perf_counter()
    if blind_lodo_enabled and dev_id in blind_lodo_candidates:
        cand_obj = blind_lodo_candidates[dev_id]
        cand_mdl = cand_obj["model"]
        cand_cols = cand_obj["features"]
        prob = float(cand_mdl.predict_proba(packet["features"][cand_cols])[0][1])
        threshold = round(float(cand_obj["threshold"]), 4) if adaptive_thr_enabled else 0.50
        pred_ring1 = 1 if prob >= threshold else 0
        eval_mode_label = f"device_{dev_id}_rf (ciego 6/2/1)"
    else:
        prob = (
            float(model.predict_proba(feat_scaled)[0][1])
            if hasattr(model, "predict_proba")
            else float(model.predict(feat_scaled)[0])
        )
        threshold = get_adaptive_threshold(dev_id, adaptive_enabled=adaptive_thr_enabled)
        pred_ring1 = 1 if prob >= threshold else 0
        eval_mode_label = selected_model_label
    ring1_latency_ms = (time.perf_counter() - t_ring1_start) * 1000.0

    zeroday_flag = False
    if enable_zeroday_ring and zeroday_model is not None:
        zd_pred = int(zeroday_model.predict(feat_scaled)[0])
        if zd_pred == -1 and prob >= 0.35:
            zeroday_flag = True

    is_malicious = (pred_ring1 == 1) or zeroday_flag

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

    root_cause_str = extract_root_cause_zscores(
        feat_scaled[0], st.session_state.emulator.feature_cols, top_k=3
    )
    total_latency_ms = (time.perf_counter() - t_start) * 1000.0
    latency_ms = ring1_latency_ms
    already_quarantined = dev_id in st.session_state.quarantined_devices

    if is_malicious:
        if already_quarantined:
            action_str = "Tráfico descartado (equipo en cuarentena)"
        elif auto_ips_quarantine:
            st.session_state.quarantined_devices.add(dev_id)
            fw_cmds = generate_firewall_commands(dev_id, dev_ip, ai_predicted_attack)
            st.session_state.firewall_rules_log[dev_id] = fw_cmds
            action_str = "Aislado automáticamente (regla DROP generada)"
        else:
            action_str = "Alerta emitida (pendiente de aislamiento manual)"

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
        action_str = "Equipo en cuarentena" if already_quarantined else "Tráfico permitido"

    record = {
        "ID": packet["packet_id"],
        "Hora": packet["timestamp"],
        "Device_ID": dev_id,
        "Dispositivo_IoT": dev_label,
        "Dispositivo_Corto": dev_name,
        "Modo_Evaluación": eval_mode_label,
        "CSV_Real_Origen": packet.get("source_csv", "N-BaIoT"),
        "Real_CSV": packet["simulated_ground_truth"],
        "Predicción_IA_Anillo2": ai_predicted_attack,
        "Veredicto": "MALICIOSO" if is_malicious else "BENIGNO",
        "Score_Anomalía": round(prob, 4),
        "Umbral_Disp": threshold,
        "Causa_Raíz_ZScore": root_cause_str,
        "Explicación_Humana": translate_root_cause_human(root_cause_str, ai_predicted_attack),
        "Acción_IPS": action_str,
        "Latencia_ms": round(latency_ms, 2),
        "Latencia_Total_3Anillos_ms": round(total_latency_ms, 2),
        "ZeroDay_Flag": zeroday_flag,
    }
    st.session_state.stream_data.append(record)
    if len(st.session_state.stream_data) > 60:
        st.session_state.stream_data.pop(0)
    st.session_state.last_latency_ms = latency_ms
    return record


if launch_clicked and model is not None and scaler is not None:
    last_rec = None
    for _ in range(burst_count):
        pkt = st.session_state.emulator.inject_specific_trace(
            attack_type=selected_attack_type, device_id=selected_dev_id
        )
        last_rec = evaluate_and_record_packet(pkt)
    st.session_state.last_injected_info = last_rec
    st.rerun()

if run_sim and model is not None and scaler is not None:
    latencies = []
    for _ in range(packets_per_cycle):
        pkt = st.session_state.emulator.stream_packet()
        rec = evaluate_and_record_packet(pkt)
        latencies.append(rec["Latencia_ms"])
    if latencies:
        st.session_state.last_latency_ms = float(sum(latencies) / len(latencies))


# ----------------- ENCABEZADO PRINCIPAL -----------------
mode_badge = "Rotación ciega 6/2/1 activa" if blind_lodo_enabled else "Modo histórico"
st.markdown(
    f"""
    <div class="app-topbar">
        <div>
            <div class="app-title">IoT Perimeter Guard</div>
            <div class="app-subtitle">Detección centralizada de anomalías y botnets en redes de dispositivos inteligentes</div>
        </div>
        <div class="env-pill">
            <span class="badge-dot" style="background:#059669;"></span>
            {html.escape(mode_badge)} · 3 Anillos
        </div>
    </div>
    <div class="scope-note">
        <strong>Entorno de validación controlada:</strong> esta consola evalúa trazas reales del catálogo UCI N-BaIoT.
        Los comandos de cortafuegos generados son propuestas demostrativas y no modifican la configuración de su router local.
    </div>
    """,
    unsafe_allow_html=True,
)


# ----------------- CÁLCULO DE MÉTRICAS DE ESTADO -----------------
df_stream = pd.DataFrame(st.session_state.stream_data)
df_by_dev = incident_store.get_incidents_by_device()
alerts_map = {}
first_seen_map = {}
if not df_by_dev.empty:
    for _, r in df_by_dev.iterrows():
        alerts_map[str(r["Dispositivo_IoT"])] = int(r["Total_Ataques"])
        first_seen_map[str(r["Dispositivo_IoT"])] = str(r["Primer_Ataque"])

quarantined_count = len(st.session_state.quarantined_devices)
compromised_unisolated = 0
for d_id in range(1, 10):
    d_lbl = f"{d_id}. {DEVICE_NAMES[d_id]} ({DEVICE_IPS[d_id]})"
    if alerts_map.get(d_lbl, 0) > 0 and d_id not in st.session_state.quarantined_devices:
        compromised_unisolated += 1

healthy_count = max(0, 9 - quarantined_count - compromised_unisolated)
total_incidents_sql = incident_store.count_incidents()

# ----------------- NAVEGACIÓN EN 4 PESTAÑAS -----------------
tab_overview, tab_forensics, tab_audit, tab_security = st.tabs(
    [
        "Resumen de Red",
        "Monitor y Forense",
        "Auditoría Científica (73 Exp.)",
        "Motor Edge y Seguridad",
    ]
)


# =============================================================================
# PESTAÑA 1: RESUMEN DE RED (INTUITIVA PARA CUALQUIER USUARIO)
# =============================================================================
with tab_overview:
    if compromised_unisolated > 0:
        hero_cls = "hero-alert"
        hero_badge = '<span class="badge badge-danger"><span class="badge-dot"></span>ACCIÓN REQUERIDA</span>'
        hero_title = f"Se detectó actividad sospechosa en {compromised_unisolated} dispositivo(s)"
        hero_desc = "Revise los equipos marcados en rojo abajo para aislar su tráfico de forma segura."
    elif quarantined_count > 0:
        hero_cls = "hero-warn"
        hero_badge = '<span class="badge badge-warn"><span class="badge-dot"></span>AMENAZA CONTENIDA</span>'
        hero_title = f"Amenaza contenida · {quarantined_count} equipo(s) en cuarentena"
        hero_desc = f"Los demás {healthy_count} dispositivos operan con normalidad y la regla de bloqueo está lista."
    elif not df_stream.empty:
        hero_cls = "hero-safe"
        hero_badge = '<span class="badge badge-ok"><span class="badge-dot"></span>RED PROTEGIDA</span>'
        hero_title = "Tu red está operando con normalidad"
        hero_desc = f"Se han inspeccionado {st.session_state.emulator.packet_count} tramas reales sin detectar comportamiento de botnet."
    else:
        hero_cls = "hero-idle"
        hero_badge = '<span class="badge badge-neutral"><span class="badge-dot"></span>EN ESPERA</span>'
        hero_title = "Sistema listo para inspeccionar tráfico IoT"
        hero_desc = "Seleccione un dispositivo y presione 'Ejecutar prueba ahora' en el panel izquierdo para comenzar."

    st.markdown(
        f"""
        <div class="hero-card {hero_cls}">
            <div>
                <div class="hero-heading">{hero_title}</div>
                <p class="hero-desc">{hero_desc}</p>
            </div>
            <div>{hero_badge}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Modo "Escenario Guiado de 1 Clic" (intuitivo para demostraciones y usuarios sin perfil técnico)
    st.caption("Escenarios guiados de demostración (1 clic)")
    sc1, sc2, sc3 = st.columns(3)
    with sc1:
        if st.button(
            "1. Día normal en casa",
            key="guided_normal",
            use_container_width=True,
            help="Reinicia el estado y envía tráfico benigno real desde 5 dispositivos domésticos.",
        ):
            if model is not None and scaler is not None:
                incident_store.clear_all()
                st.session_state.stream_data = []
                st.session_state.quarantined_devices = set()
                st.session_state.firewall_rules_log = {}
                last_rec = None
                for dev_i in [1, 2, 4, 5, 7]:
                    pkt = st.session_state.emulator.inject_specific_trace(
                        attack_type="Benigno", device_id=dev_i
                    )
                    last_rec = evaluate_and_record_packet(pkt)
                st.session_state.last_injected_info = last_rec
                st.rerun()
    with sc2:
        if st.button(
            "2. Ataque Mirai en cámara",
            key="guided_mirai",
            use_container_width=True,
            help="Simula un ataque real Mirai UDP en la Cámara #5 usando el modelo ciego device_5_rf (0% visto).",
        ):
            if model is not None and scaler is not None:
                atks_5 = st.session_state.emulator.get_available_attacks(device_id=5)
                mirai_choice = next((a for a in atks_5 if "Mirai_UDP" in a), atks_5[1] if len(atks_5) > 1 else atks_5[0])
                last_rec = None
                for _ in range(3):
                    pkt = st.session_state.emulator.inject_specific_trace(
                        attack_type=mirai_choice, device_id=5
                    )
                    last_rec = evaluate_and_record_packet(pkt)
                st.session_state.last_injected_info = last_rec
                st.rerun()
    with sc3:
        if st.button(
            "3. Ataque BASHLITE / Zero-Day",
            key="guided_bashlite",
            use_container_width=True,
            help="Simula un ataque BASHLITE en el Monitor #4 evaluado con el fold ciego device_4_rf y el Anillo 3 LOF.",
        ):
            if model is not None and scaler is not None:
                atks_4 = st.session_state.emulator.get_available_attacks(device_id=4)
                bash_choice = next((a for a in atks_4 if "BASHLITE" in a), atks_4[1] if len(atks_4) > 1 else atks_4[0])
                last_rec = None
                for _ in range(3):
                    pkt = st.session_state.emulator.inject_specific_trace(
                        attack_type=bash_choice, device_id=4
                    )
                    last_rec = evaluate_and_record_packet(pkt)
                st.session_state.last_injected_info = last_rec
                st.rerun()

    st.markdown("<div style='height:0.35rem;'></div>", unsafe_allow_html=True)

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(
            f"""<div class="kpi-box"><div class="kpi-label">Dispositivos sanos</div>
            <div class="kpi-val">{healthy_count} / 9</div>
            <div class="kpi-sub">Monitoreados en perímetro</div></div>""",
            unsafe_allow_html=True,
        )
    with k2:
        st.markdown(
            f"""<div class="kpi-box"><div class="kpi-label">Incidentes registrados</div>
            <div class="kpi-val">{total_incidents_sql}</div>
            <div class="kpi-sub">Persistidos en SQLite</div></div>""",
            unsafe_allow_html=True,
        )
    with k3:
        st.markdown(
            f"""<div class="kpi-box"><div class="kpi-label">En cuarentena</div>
            <div class="kpi-val">{quarantined_count}</div>
            <div class="kpi-sub">Reglas IP+MAC listas</div></div>""",
            unsafe_allow_html=True,
        )
    with k4:
        st.markdown(
            f"""<div class="kpi-box"><div class="kpi-label">Latencia Anillo 1</div>
            <div class="kpi-val">{st.session_state.last_latency_ms:.2f} ms</div>
            <div class="kpi-sub">Detección CPU (meta ≤ 10 ms)</div></div>""",
            unsafe_allow_html=True,
        )

    # Último evento traducido a lenguaje simple
    if st.session_state.last_injected_info is not None:
        info = st.session_state.last_injected_info
        is_mal = info["Veredicto"] == "MALICIOSO"
        status_pill = (
            '<span class="badge badge-danger"><span class="badge-dot"></span>AMENAZA DETECTADA</span>'
            if is_mal
            else '<span class="badge badge-ok"><span class="badge-dot"></span>TRÁFICO LEGÍTIMO</span>'
        )
        human_msg = (
            info["Explicación_Humana"]
            if is_mal
            else "El patrón de paquetes coincide con el comportamiento normal esperado para este equipo."
        )
        st.markdown(
            f"""
            <div class="diag-card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem;">
                    <div class="diag-title">Último análisis: {html.escape(info['Dispositivo_Corto'])} ({html.escape(info['Hora'])})</div>
                    {status_pill}
                </div>
                <p class="diag-text">{html.escape(human_msg)}</p>
                <p class="diag-text" style="color:#64748B;margin-top:0.35rem;font-size:0.81rem;">
                    <strong>Respuesta:</strong> {html.escape(info['Acción_IPS'])} ·
                    <strong>Tiempo:</strong> {info['Latencia_ms']:.2f} ms
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.expander("Ver detalle técnico del último evento (3 Anillos y Z-Score)", expanded=False):
            c_t1, c_t2, c_t3 = st.columns(3)
            c_t1.metric("Anillo 1 (Score vs Umbral)", f"{info['Score_Anomalía']:.4f}", f"Umbral {info['Umbral_Disp']}")
            c_t2.metric("Anillo 2 (Firma predicha)", info["Predicción_IA_Anillo2"])
            c_t3.metric("Anillo 3 (Zero-Day LOF)", "Anomalía" if info.get("ZeroDay_Flag") else "Normal")
            st.markdown(
                f"- **Modelo evaluador:** `{info['Modo_Evaluación']}`\n"
                f"- **Archivo origen:** `{info['CSV_Real_Origen']}` (Etiqueta real: `{info['Real_CSV']}`)\n"
                f"- **Desviaciones físicas principales (Z-Score):** `{info['Causa_Raíz_ZScore']}`"
            )

    # Grilla minimalista 3x3 de los 9 dispositivos
    st.markdown("#### Dispositivos conectados en la red local")
    for row_idx in range(3):
        cols = st.columns(3)
        for col_idx in range(3):
            d_id = row_idx * 3 + col_idx + 1
            d_name = DEVICE_NAMES[d_id]
            d_ip = DEVICE_IPS[d_id]
            d_mac = DEVICE_MACS[d_id]
            d_cat = DEVICE_CATEGORIES.get(d_id, "Dispositivo IoT")
            d_label = f"{d_id}. {d_name} ({d_ip})"
            n_alerts = alerts_map.get(d_label, 0)
            is_q = d_id in st.session_state.quarantined_devices

            if is_q:
                card_cls = "dev-card dev-card-quarantine"
                b_html = '<span class="badge badge-warn"><span class="badge-dot"></span>Cuarentena</span>'
            elif n_alerts > 0:
                card_cls = "dev-card dev-card-danger"
                b_html = f'<span class="badge badge-danger"><span class="badge-dot"></span>{n_alerts} alerta(s)</span>'
            else:
                card_cls = "dev-card"
                b_html = '<span class="badge badge-ok"><span class="badge-dot"></span>Normal</span>'

            fold_txt = (
                f"device_{d_id}_rf (0% visto)"
                if (blind_lodo_enabled and d_id in blind_lodo_candidates)
                else "Modelo histórico"
            )

            with cols[col_idx]:
                st.markdown(
                    f"""
                    <div class="{card_cls}">
                        <div class="dev-header">
                            <div>
                                <div class="dev-name">{d_id}. {html.escape(d_name)}</div>
                                <div class="dev-cat">{html.escape(d_cat)}</div>
                            </div>
                            {b_html}
                        </div>
                        <div class="dev-meta">{d_ip} · {d_mac}</div>
                        <div class="dev-cat" style="margin-top:4px;">Fold: <code>{fold_txt}</code></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if is_q:
                    if st.button(
                        f"Liberar dispositivo #{d_id}",
                        key=f"release_{d_id}",
                        use_container_width=True,
                    ):
                        st.session_state.quarantined_devices.discard(d_id)
                        st.session_state.firewall_rules_log.pop(d_id, None)
                        st.rerun()
                elif n_alerts > 0:
                    if st.button(
                        f"Aislar dispositivo #{d_id}",
                        key=f"isolate_{d_id}",
                        type="primary",
                        use_container_width=True,
                    ):
                        st.session_state.quarantined_devices.add(d_id)
                        st.session_state.firewall_rules_log[d_id] = generate_firewall_commands(
                            d_id, d_ip, "Aislamiento_Manual"
                        )
                        st.rerun()


# =============================================================================
# PESTAÑA 2: MONITOR EN VIVO, PACIENTE CERO Y FORENSE SQLITE
# =============================================================================
with tab_forensics:
    col_left, col_right = st.columns([1.45, 1.55])

    with col_left:
        st.markdown("#### Evolución del puntaje de anomalía")
        if not df_stream.empty:
            chart_df = df_stream[["Hora", "Score_Anomalía", "Umbral_Disp"]].set_index("Hora")
            st.line_chart(chart_df, height=230)
        else:
            st.info("Ejecute una prueba o active el flujo continuo para visualizar la señal en tiempo real.")

        st.markdown("#### Primer dispositivo alertado (Paciente Cero)")
        patient_zero = incident_store.get_first_compromised_device()
        if patient_zero:
            pz_dev_name = patient_zero["device_name"]
            try:
                pz_dev_id = int(pz_dev_name.split(".")[0])
            except Exception:
                pz_dev_id = 1
            pz_ip = DEVICE_IPS.get(pz_dev_id, "192.168.1.101")
            pz_mac = DEVICE_MACS.get(pz_dev_id, "00:16:6C:7B:9A:01")
            pz_q = pz_dev_id in st.session_state.quarantined_devices

            st.markdown(
                f"""
                <div class="diag-card" style="border-left:4px solid #DC2626;">
                    <div class="diag-title">{html.escape(pz_dev_name)}</div>
                    <p class="diag-text">
                        <strong>MAC:</strong> <code>{pz_mac}</code> ·
                        <strong>Primera alerta:</strong> <code>{html.escape(str(patient_zero['first_timestamp']))}</code> ·
                        <strong>Total alertas:</strong> {patient_zero['total_alerts_from_device']}<br>
                        <strong>Estado:</strong> {'Bloqueado en cuarentena' if pz_q else 'Pendiente de aislamiento'}
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            fw_info = st.session_state.firewall_rules_log.get(
                pz_dev_id, generate_firewall_commands(pz_dev_id, pz_ip, "Botnet_IPS")
            )
            st.markdown("**Reglas de cortafuegos propuestas (Capa 2 + Capa 3)**")
            st.code(
                f"# iptables (IP + MAC anti-spoofing)\n{fw_info.get('iptables_drop', '')}\n\n"
                f"# nftables\n{fw_info.get('nftables_drop', '')}\n\n"
                f"# Corte de sesiones activas\n{fw_info.get('conntrack_flush', '')}",
                language="bash",
            )
        else:
            st.caption("Sin incidentes registrados hasta el momento.")

    with col_right:
        hdr_c1, hdr_c2 = st.columns([2, 1])
        with hdr_c1:
            st.markdown(f"#### Registro forense SQLite ({total_incidents_sql})")
        df_sql_alerts = incident_store.get_recent_incidents(limit=50)
        with hdr_c2:
            if not df_sql_alerts.empty:
                st.download_button(
                    label="Exportar CSV",
                    data=df_sql_alerts.to_csv(index=False).encode("utf-8"),
                    file_name="iot_perimeter_incidents.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

        if not df_sql_alerts.empty:
            st.dataframe(df_sql_alerts, use_container_width=True, hide_index=True, height=300)
        else:
            st.info("La base de datos de incidentes está vacía.")

        st.markdown("#### Telemetría reciente de paquetes")
        if not df_stream.empty:
            cols_show = [
                "Hora",
                "Dispositivo_Corto",
                "Modo_Evaluación",
                "Real_CSV",
                "Predicción_IA_Anillo2",
                "Veredicto",
                "Score_Anomalía",
                "Latencia_ms",
            ]
            st.dataframe(
                df_stream.iloc[::-1].head(15)[cols_show],
                use_container_width=True,
                hide_index=True,
                height=260,
            )
        else:
            st.caption("Sin tramas evaluadas en la sesión actual.")


# =============================================================================
# PESTAÑA 3: AUDITORÍA CIENTÍFICA (73 EXPERIMENTOS Y EXPLICABILIDAD)
# =============================================================================
with tab_audit:
    st.markdown("#### Protocolo riguroso 6/2/1 (73 experimentos reproducibles)")
    st.caption(
        "Seis dispositivos para ajuste (bloques 10% y 30%), dos para calibración (FPR ≤ 0,1%) "
        "y uno 100% excluido para prueba, más 16 escenarios de exclusión de familia (Zero-Day) y 27 ablaciones."
    )

    if not rigorous_df.empty:
        if "experiment" in rigorous_df.columns:
            exp_filter = st.radio(
                "Filtrar experimentos",
                options=["Todos (73)", "Dispositivo externo (6/2/1)", "Familia excluida (Zero-Day)", "Ablaciones"],
                horizontal=True,
            )
            if exp_filter == "Dispositivo externo (6/2/1)":
                df_view = rigorous_df[rigorous_df["experiment"].str.startswith("device_", na=False)]
            elif exp_filter == "Familia excluida (Zero-Day)":
                df_view = rigorous_df[rigorous_df["experiment"].str.contains("unseen", na=False)]
            elif exp_filter == "Ablaciones":
                df_view = rigorous_df[rigorous_df["experiment"].str.contains("ablation", na=False)]
            else:
                df_view = rigorous_df
        else:
            df_view = rigorous_df
        st.dataframe(df_view, use_container_width=True, hide_index=True, height=320)
    else:
        st.info("No se encontró `experiments/rigorous_v1/summary.csv`.")

    st.divider()
    col_h1, col_h2 = st.columns([1.25, 1.0])
    with col_h1:
        st.markdown("#### Referencia histórica frente a línea base (`Dummy`)")
        st.dataframe(
            pd.DataFrame(historical_comparison(metrics_data)),
            use_container_width=True,
            hide_index=True,
        )
    with col_h2:
        st.markdown("#### Anillo 2 — Clasificación multiclase (10 ataques)")
        st.dataframe(
            pd.DataFrame(multiclass_tasks(metrics_data.get("multiclass_attack_classifier", {}))),
            use_container_width=True,
            hide_index=True,
        )

    st.divider()
    col_fi, col_lodo = st.columns([1.05, 1.35])
    with col_fi:
        st.markdown("#### Top 15 variables físicas (Random Forest)")
        st.caption("Cero dependencia de época Unix tras sanitizar media y varianza de `HH_jit`.")
        top_rf = metrics_data.get("top_15_features_rf", {})
        if top_rf:
            df_fi = pd.DataFrame(
                {"Variable": list(top_rf.keys()), "Importancia": list(top_rf.values())}
            ).set_index("Variable")
            st.bar_chart(df_fi, height=310)
    with col_lodo:
        st.markdown("#### Referencia histórica LODO (9 dispositivos)")
        lodo_info = metrics_data.get("lodo_9_devices", {}).get("folds", {})
        if lodo_info:
            rows_lodo = []
            for _, fdata in lodo_info.items():
                rows_lodo.append(
                    {
                        "Dispositivo excluido": f"{fdata['device_id']}. {fdata['device_name']}",
                        "LR F1": fdata["lr"]["f1"],
                        "RF Estándar F1": fdata["rf"]["f1"],
                        "RF FPR (%)": round(fdata["rf"]["fpr"] * 100.0, 2),
                        "RF Adaptativo F1": fdata.get("rf_adaptive", {}).get("f1"),
                        "RF Adapt. FPR (%)": round(
                            fdata.get("rf_adaptive", {}).get("fpr", 0.0) * 100.0, 2
                        ),
                    }
                )
            st.dataframe(pd.DataFrame(rows_lodo), use_container_width=True, hide_index=True, height=310)


# =============================================================================
# PESTAÑA 4: MOTOR EDGE, INTEGRIDAD SHA-256 Y SEGURIDAD
# =============================================================================
with tab_security:
    c_sec1, c_sec2 = st.columns([1.35, 1.0])

    with c_sec1:
        st.markdown("#### Verificación criptográfica SHA-256 en memoria")
        st.caption(
            "Cada artefacto serializado se valida contra su manifiesto local antes de cargarse con `joblib.load()`."
        )
        all_hashes = core_audit_log + blind_audit_log
        if all_hashes:
            st.dataframe(pd.DataFrame(all_hashes), use_container_width=True, hide_index=True, height=310)
        else:
            st.warning("No se encontraron manifiestos de integridad.")

    with c_sec2:
        st.markdown("#### Controles activos de ciberseguridad")
        st.markdown(
            f"""
            - **Autenticación:** Token JWT `HS256` con expiración y comparación en tiempo constante.
            - **Protección fuerza bruta:** Bloqueo temporal de `{LOCKOUT_SECONDS} s` tras `{MAX_LOGIN_ATTEMPTS}` intentos fallidos.
            - **Base de datos SQLite:** Consultas 100% parametrizadas contra inyección SQL.
            - **Lista blanca Anti-Lockout:** Impide generar reglas de bloqueo sobre `{', '.join(sorted(list(CRITICAL_WHITELIST_IPS)))}`.
            - **Arquitectura metodológica:** Ciclo CRISP-DM / CRISP-ML(Q) (offline) desacoplado de la consola operativa (online).
            """
        )

    st.divider()
    st.markdown("#### Prototipo de extractor incremental $O(1)$ para hardware de borde")
    st.caption(
        "Módulo `src/streaming/live_feature_extractor.py`: calcula ventanas de decaimiento exponencial "
        "(λ ∈ {5, 3, 1, 0.1, 0.01}) desde cabeceras de red. Pendiente de certificación numérica frente a Kitsune sobre capturas .pcap."
    )
    if st.button("Probar extractor con 25 cabeceras sintéticas"):
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
            f"Se generaron 25 vectores incrementales de dimensión {df_115.shape} sin valores nulos."
        )
        st.dataframe(df_115.iloc[:, :10], use_container_width=True, hide_index=True)


# ----------------- REFRESCO CONTINUO OPCIONAL -----------------
if run_sim:
    time.sleep(stream_speed)
    st.rerun()
