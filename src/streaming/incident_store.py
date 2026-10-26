"""Persistencia histórica de incidentes de ciberseguridad en SQLite (consultas parametrizadas)."""

import os
import sqlite3
from contextlib import closing
from typing import Optional
import pandas as pd

DEFAULT_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "incidents_history.db")
)


class IncidentStore:
    """Almacén relacional SQLite para trazabilidad histórica de alertas de red."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        device_name TEXT NOT NULL,
                        model_name TEXT NOT NULL,
                        attack_type TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        action TEXT NOT NULL
                    )
                    """
                )

    def log_incident(
        self,
        timestamp: str,
        model_name: str,
        attack_type: str,
        confidence: float,
        action: str = "Alerta enviada a Gateway",
        device_name: str = "Gateway Router (N-BaIoT)",
    ) -> int:
        """Registra un incidente detectado usando SQL parametrizado contra inyección."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cur = conn.execute(
                    """
                    INSERT INTO incidents (timestamp, device_name, model_name, attack_type, confidence, action)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(timestamp),
                        str(device_name),
                        str(model_name),
                        str(attack_type),
                        round(float(confidence) * 100.0, 2),
                        str(action),
                    ),
                )
                return int(cur.lastrowid)

    def get_recent_incidents(self, limit: int = 20) -> pd.DataFrame:
        """Retorna las alertas más recientes para su visualización en el Dashboard."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            return pd.read_sql_query(
                """
                SELECT
                    id AS ID,
                    timestamp AS Timestamp,
                    model_name AS Modelo,
                    attack_type AS Tipo_Ataque,
                    printf('%.1f%%', confidence) AS Confianza,
                    action AS Accion
                FROM incidents
                ORDER BY id DESC
                LIMIT ?
                """,
                conn,
                params=(int(limit),),
            )

    def count_incidents(self) -> int:
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()
            return int(row[0]) if row else 0

    def clear_all(self) -> None:
        """Elimina todos los registros de la tabla de incidentes para reiniciar la demo."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute("DELETE FROM incidents")
                try:
                    conn.execute("DELETE FROM sqlite_sequence WHERE name='incidents'")
                except sqlite3.OperationalError:
                    pass
