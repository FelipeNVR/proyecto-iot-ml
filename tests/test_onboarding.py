"""Pruebas unitarias para el gestor dinámico de incorporación (Modo Aprendizaje 24h e Invitados)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.streaming.device_onboarding import DeviceOnboardingManager


class TestDeviceOnboardingManager(unittest.TestCase):
    def setUp(self):
        self.mgr = DeviceOnboardingManager()

    def test_learning_24h_auto_calibrates_personal_threshold(self):
        dev = self.mgr.register_iot_device("Cámara Tapo C200", target_samples=10)
        self.assertEqual(dev.profile_mode, "LEARNING_24H")
        self.assertEqual(dev.device_id, 10)

        # Simular 10 muestras benignas con picos legítimos hasta 0.62 (ej. streaming HD)
        benign_scores = [0.10, 0.12, 0.15, 0.20, 0.25, 0.30, 0.45, 0.55, 0.60, 0.62]
        for s in benign_scores:
            res = self.mgr.evaluate_packet_policy(dev.device_id, s)
            self.assertFalse(res["blocked"])

        self.assertEqual(dev.profile_mode, "PROTECTED")
        self.assertEqual(dev.calibrated_at_hours, 24.0)
        # Q99.5 de benign_scores (~0.6191) + 0.05 ≈ 0.6691
        self.assertGreaterEqual(dev.personal_threshold, 0.65)
        self.assertLessEqual(dev.personal_threshold, 0.95)
        self.assertEqual(dev.false_alarms_avoided, 3)  # 0.55, 0.60, 0.62 habrían disparado 0.50

    def test_learning_24h_fail_open_never_blocks_prematurely(self):
        dev = self.mgr.register_iot_device("Sensor Nuevo", target_samples=20)
        res = self.mgr.evaluate_packet_policy(dev.device_id, 0.98, auto_quarantine=True)
        self.assertFalse(res["blocked"])
        self.assertEqual(res["verdict"], "ALERTA_EN_APRENDIZAJE")
        self.assertFalse(dev.quarantined)

    def test_birthday_guest_burst_activates_social_mode(self):
        guests = self.mgr.register_guest_burst(count=9)
        self.assertEqual(len(guests), 9)
        self.assertTrue(self.mgr.social_event_active)
        self.assertEqual([g.device_id for g in guests], list(range(10, 19)))
        for g in guests:
            self.assertEqual(g.profile_mode, "GUEST_MONITOR_ONLY")
            self.assertEqual(g.personal_threshold, 0.85)
            self.assertFalse(g.quarantined)

    def test_guest_mode_alerts_surgically_without_blocking_others(self):
        guests = self.mgr.register_guest_burst(count=9)
        # Tráfico normal/streaming (0.65) de los primeros 8 invitados no genera alertas ni bloqueos
        for g in guests[:8]:
            res = self.mgr.evaluate_packet_policy(g.device_id, 0.65)
            self.assertEqual(res["verdict"], "BENIGNO")
            self.assertFalse(res["blocked"])
            self.assertEqual(g.false_alarms_avoided, 1)

        # El invitado #9 lanza un ataque claro (0.97): alerta quirúrgica solo a él
        res_atk = self.mgr.evaluate_packet_policy(guests[8].device_id, 0.97)
        self.assertEqual(res_atk["verdict"], "MALICIOSO")
        self.assertFalse(res_atk["blocked"])
        self.assertEqual(guests[8].alerts_count, 1)
        self.assertEqual(sum(g.alerts_count for g in guests[:8]), 0)

    def test_protected_calibrated_device_blocks_attack_above_personal_threshold(self):
        dev = self.mgr.register_iot_device("Cámara Nueva", target_samples=5)
        for s in [0.05, 0.08, 0.10, 0.12, 0.15]:
            self.mgr.observe_benign_score(dev.device_id, s)
        self.assertEqual(dev.profile_mode, "PROTECTED")
        self.assertEqual(dev.personal_threshold, 0.50)

        res = self.mgr.evaluate_packet_policy(dev.device_id, 0.96, auto_quarantine=True)
        self.assertEqual(res["verdict"], "MALICIOSO")
        self.assertTrue(res["blocked"])
        self.assertTrue(dev.quarantined)


if __name__ == "__main__":
    unittest.main()
