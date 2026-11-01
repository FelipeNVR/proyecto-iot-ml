"""Suite de pruebas automatizadas (unittest / pytest) para validar el pipeline ML, seguridad y MVP."""

import os
import sys
import json
import tempfile
import unittest
import numpy as np
import pandas as pd

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT_DIR)

from src.data.preprocess import (
    chronological_split,
    sanitize_jitter_features,
    load_single_device_splits,
    META_COLS,
)
from src.streaming.emulator import IoTTrafficStreamEmulator
from src.streaming.incident_store import IncidentStore
from src.streaming.live_feature_extractor import LiveAfterImageExtractor
from src.streaming.firewall_controller import (
    get_adaptive_threshold,
    extract_root_cause_zscores,
    verify_whitelist_safety,
    generate_firewall_commands,
)
from src.models.baseline import compute_sha256


class TestIoTAnomalyDetectionPipeline(unittest.TestCase):
    """Pruebas de regresión, no-fuga de datos, seguridad criptográfica y rendimiento."""

    def test_01_chronological_split_no_leakage(self):
        """Verifica que la partición temporal con purga (65/15/15 + 2.5% embargo) respete el orden y la brecha temporal."""
        df = pd.DataFrame({"t": np.arange(1000), "val": np.random.randn(1000)})
        tr, va, te = chronological_split(
            df, train_frac=0.65, val_frac=0.15, purge_frac=0.025
        )
        self.assertEqual(len(tr), 650)
        self.assertEqual(len(va), 150)
        self.assertEqual(len(te), 150)
        self.assertGreaterEqual(va["t"].min() - tr["t"].max(), 25)
        self.assertGreaterEqual(te["t"].min() - va["t"].max(), 25)

    def test_02_jitter_sanitization_compresses_unix_epoch(self):
        """Verifica que sanitize_jitter_features comprima la marca de tiempo Unix (~1.5e9) sin producir NaN."""
        df = pd.DataFrame(
            {
                "HH_jit_L0.1_mean": [10.0, 1.507655e9, 0.0],
                "MI_dir_L0.1_weight": [1.0, 2.0, 3.0],
            }
        )
        clean = sanitize_jitter_features(df)
        self.assertFalse(clean.isna().any().any())
        self.assertLess(clean["HH_jit_L0.1_mean"].max(), 25.0)
        self.assertEqual(clean["MI_dir_L0.1_weight"].tolist(), [1.0, 2.0, 3.0])

    def test_03_device_3_without_mirai_loads_balanced(self):
        """Verifica que el Dispositivo 3 (Ennio Doorbell, sin archivos Mirai) cargue sus 5 ataques BASHLITE."""
        tr, va, te = load_single_device_splits(
            device_id=3, sample_benign=500, sample_attack=500
        )
        feature_cols = [c for c in tr.columns if c not in META_COLS]
        self.assertEqual(len(feature_cols), 115)
        self.assertIn(0, tr["target"].unique())
        self.assertIn(1, tr["target"].unique())

    def test_04_artifacts_sha256_and_latency_criteria(self):
        """Verifica que los artefactos .pkl coincidan con su firma SHA-256 y cumplan latencia <= 10 ms."""
        registry_dir = os.path.join(ROOT_DIR, "models_registry")
        manifest_path = os.path.join(registry_dir, "artifacts_sha256.json")
        metrics_path = os.path.join(registry_dir, "baseline_metrics.json")

        self.assertTrue(os.path.exists(manifest_path), "Falta artifacts_sha256.json")
        self.assertTrue(os.path.exists(metrics_path), "Falta baseline_metrics.json")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        for fname, expected_hash in manifest.items():
            fpath = os.path.join(registry_dir, fname)
            self.assertTrue(os.path.exists(fpath), f"Falta artefacto {fname}")
            self.assertEqual(compute_sha256(fpath), expected_hash)

        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)

        # Criterio 1 (F1 >= 0.95) y Criterio 3 (Latencia <= 10 ms por paquete)
        for m_key in [
            "baseline_logistic_regression",
            "decision_tree",
            "random_forest",
            "gradient_boosting",
            "svm_calibrated",
        ]:
            self.assertGreaterEqual(metrics[m_key]["f1_score"], 0.95)
            self.assertLessEqual(
                metrics[m_key]["inference_ms_single_packet"],
                10.0,
                f"{m_key} excede 10 ms por paquete",
            )

    def test_05_emulator_respects_anomaly_prob(self):
        """Verifica que el emulador respete anomaly_prob=0.0 (100% benigno) y anomaly_prob=1.0 (100% ataque)."""
        emu = IoTTrafficStreamEmulator(anomaly_prob=0.0)
        for _ in range(15):
            pkt = emu.stream_packet()
            self.assertEqual(pkt["simulated_ground_truth"], "Benigno")
            self.assertEqual(pkt["features"].shape, (1, 115))

        emu.anomaly_prob = 1.0
        for _ in range(15):
            pkt = emu.stream_packet()
            self.assertNotEqual(pkt["simulated_ground_truth"], "Benigno")

    def test_06_sqlite_incident_store_parameterized(self):
        """Verifica inserción y consulta parametrizada en SQLite (incluyendo resistencia a payloads SQLi) y borrado."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = os.path.join(tmpdir, "test_incidents.db")
            store = IncidentStore(db_path=db_file)
            sqli_payload = "Mirai_UDP'; DROP TABLE incidents;--"
            row_id = store.log_incident(
                timestamp="12:00:00",
                model_name="Random Forest",
                attack_type=sqli_payload,
                confidence=0.994,
            )
            self.assertGreater(row_id, 0)
            self.assertEqual(store.count_incidents(), 1)
            df_inc = store.get_recent_incidents(limit=5)
            self.assertEqual(df_inc.iloc[0]["Tipo_Ataque"], sqli_payload)

            # Test clear_all
            store.clear_all()
            self.assertEqual(store.count_incidents(), 0)

    def test_07_real_trace_injection_and_patient_zero(self):
        """Verifica la inyección de trazas reales por dispositivo/ataque y la detección de Paciente Cero."""
        emu = IoTTrafficStreamEmulator()
        pkt = emu.inject_specific_trace(attack_type="Mirai_SYN", device_id=5)
        self.assertEqual(pkt["device_id"], 5)
        self.assertEqual(pkt["simulated_ground_truth"], "Mirai_SYN")
        self.assertEqual(pkt["source_csv"], "5.mirai.syn.csv")
        self.assertEqual(pkt["features"].shape, (1, 115))

        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = os.path.join(tmpdir, "test_pz.db")
            store = IncidentStore(db_path=db_file)
            store.log_incident(
                timestamp="10:01:00",
                model_name="Random Forest",
                attack_type="Mirai_SYN [5.mirai.syn.csv]",
                confidence=0.99,
                device_name="5. Provision PT-737E Security Camera (192.168.1.105)",
            )
            store.log_incident(
                timestamp="10:02:00",
                model_name="Random Forest",
                attack_type="BASHLITE_UDP [2.gafgyt.udp.csv]",
                confidence=0.98,
                device_name="2. Ecobee Thermostat (192.168.1.102)",
            )
            pz = store.get_first_compromised_device()
            self.assertIsNotNone(pz)
            self.assertIn("Provision PT-737E", pz["device_name"])
            self.assertEqual(pz["first_timestamp"], "10:01:00")

    def test_08_three_ring_defense_models_and_metrics(self):
        """Verifica que los Anillos 2 (Multiclase 10 Ataques) y 3 (Zero-Day) estén operativos y calibrados."""
        registry_dir = os.path.join(ROOT_DIR, "models_registry")
        metrics_path = os.path.join(registry_dir, "baseline_metrics.json")
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)

        self.assertIn("multiclass_attack_classifier", metrics)
        self.assertEqual(metrics["multiclass_attack_classifier"]["n_classes"], 10)
        self.assertGreaterEqual(metrics["multiclass_attack_classifier"]["accuracy"], 0.75)

        self.assertIn("zeroday_isolation_forest", metrics)
        self.assertGreaterEqual(
            metrics["zeroday_isolation_forest"]["attack_detection_recall"], 0.70
        )

    def test_09_live_afterimage_feature_extractor(self):
        """Verifica el motor de extracción incremental O(1) de 115 características para tráfico en vivo."""
        emu = IoTTrafficStreamEmulator()
        extractor = LiveAfterImageExtractor(feature_columns=emu.feature_cols)
        df_vec = None
        for i in range(15):
            df_vec = extractor.process_raw_packet(
                src_mac="00:16:6c:7f:82:05",
                src_ip="192.168.1.105",
                dst_ip="198.51.100.44",
                src_port=49152 + i,
                dst_port=80,
                pkt_size=512.0,
                timestamp=1700000000.0 + i * 0.002,
            )
        self.assertEqual(df_vec.shape, (1, 115))
        self.assertFalse(df_vec.isna().any().any())
        self.assertGreater(float(df_vec["MI_dir_L5_weight"].iloc[0]), 1.0)

    def test_10_active_ips_firewall_controller_and_whitelist(self):
        """Verifica la protección Anti-Lockout (Whitelist) y generación de comandos iptables/nftables."""
        safe_gw, reason_gw = verify_whitelist_safety("192.168.1.1")
        self.assertFalse(safe_gw)
        self.assertIn("BLOQUEO RECHAZADO", reason_gw)

        safe_iot, _ = verify_whitelist_safety("192.168.1.105")
        self.assertTrue(safe_iot)

        cmds = generate_firewall_commands(
            device_id=5,
            device_ip="192.168.1.105",
            attack_signature="Mirai_UDP",
        )
        self.assertEqual(cmds["status"], "READY")
        self.assertIn("iptables -I FORWARD 1 -s 192.168.1.105", cmds["iptables_drop"])
        self.assertIn("conntrack -D -s 192.168.1.105", cmds["conntrack_flush"])
        self.assertEqual(get_adaptive_threshold(4), 0.72)
        self.assertEqual(get_adaptive_threshold(1), 0.50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
