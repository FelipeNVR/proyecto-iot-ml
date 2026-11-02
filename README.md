# 🛡️ Sistema Centralizado de Detección de Anomalías en Redes IoT (CINF200)

## Estado experimental actualizado — 1 de noviembre de 2026

El protocolo recomendado es [VALIDACION_REAL.md](VALIDACION_REAL.md). Se incorporó
`src/models/rigorous.py`: bloques repartidos a lo largo de las capturas, prueba en
dispositivo excluido, calibración en otros dispositivos y exclusión de botnets.
Las métricas históricas que siguen abajo no acreditan preparación para producción.
El dashboard reproduce un catálogo CSV; no captura por sí mismo tráfico de tu router.
El extractor online es experimental y necesita equivalencia numérica contra una referencia.

Desde esta carpeta, para una ejecución nueva sin sobrescribir resultados:

```powershell
.\venv\Scripts\python.exe -m src.models.rigorous --output experiments\rigorous_nueva_ejecucion
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

`experiments/rigorous_v1` contiene la primera ejecución del protocolo nuevo (73 experimentos). Sus
candidatos (`device_1_rf` a `device_9_rf`) se guardan separados de `models_registry`, verificados con `candidate_hashes.json`, y el Dashboard permite enrutarlos dinámicamente por dispositivo atacado mediante el modo **Evaluación Ciega 6/2/1**.
La sección antigua de entrenamiento mediante `baseline.py` queda como reproducción histórica.

**Autor:** Felipe Nicolás Vergara Rodríguez — Ingeniería Civil Informática, Universidad Andrés Bello (Sede Viña del Mar).  
**Docente Tutor:** Nicolás Caselli Benavente.  
**Dataset:** [UCI N-BaIoT Dataset](https://doi.org/10.24432/C5RC8J) (Meidan et al., *IEEE Pervasive Computing*, 2018) — 9 dispositivos IoT comerciales, 115 características por muestra, botnets **Mirai** y **BASHLITE (gafgyt)**.

---

## 🏗️ Arquitectura del Repositorio

```text
proyecto-iot-ml/
├── app/
│   └── app.py                       # Dashboard MVP en Streamlit (JWT HS256, SQLite, Feature Importance, LODO)
├── data/
│   ├── 1.benign.csv ... 9.mirai.*   # 89 archivos CSV reales del dataset N-BaIoT
│   ├── data_summary.csv             # Conteo oficial de muestras por archivo
│   ├── device_info.csv              # Catálogo de los 9 dispositivos IoT
│   ├── stream_sample_real.csv       # Muestra equilibrada del conjunto Test para emulación en vivo
│   └── incidents_history.db         # Base de datos relacional SQLite de incidentes detectados
├── models_registry/
│   ├── scaler_nbaiot.pkl            # StandardScaler ajustado exclusivamente en Train
│   ├── model_baseline_lr.pkl        # Línea Base: Regresión Logística
│   ├── model_candidate_dt.pkl       # Árbol de Decisión (max_depth=8)
│   ├── model_random_forest.pkl      # Ensamble Random Forest (n_estimators=100, max_depth=12)
│   ├── model_gradient_boosting.pkl  # HistGradientBoostingClassifier
│   ├── model_svm.pkl                # LinearSVC con calibración sigmoide (Platt scaling)
│   ├── artifacts_sha256.json        # Manifiesto criptográfico SHA-256 contra deserialización insegura
│   ├── baseline_metrics.json        # Métricas completas (65/15/15 + 5-Fold CV + Latencia + Top 15 Features)
│   └── lodo_metrics.json            # Resultados de los 9 folds Leave-One-Device-Out (LODO) + test de Wilcoxon
├── src/
│   ├── data/
│   │   └── preprocess.py            # Ingesta de 10 ataques, estabilización HH_jit y partición temporal 65/15/15 (+purga)
│   ├── models/
│   │   └── baseline.py              # Entrenamiento de línea base + 4 modelos, 5-Fold CV y LODO
│   └── streaming/
│       ├── emulator.py              # Emulador de tráfico en vivo controlado por probabilidad de ataque
│       └── incident_store.py        # Persistencia relacional SQLite con consultas parametrizadas
├── tests/
│   └── test_pipeline.py             # Suite de pruebas unitarias, de integración y regresión
├── 01_exploracion_dataset.ipynb     # Notebook exploratorio ejecutado con estadísticas de los 9 dispositivos
└── requirements.txt                 # Dependencias del proyecto
```

---

## 🚀 Ejecución Reproducible Desde Cero

### 1. Activar entorno e instalar dependencias
```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Ejecutar el Pipeline Offline (Entrenamiento + 5-Fold CV + Validación LODO 9 Dispositivos)
```powershell
.\venv\Scripts\python.exe src/models/baseline.py
```

### 3. Ejecutar la Suite de Pruebas Automatizadas (20 tests de contratos, protocolo 6/2/1 y regresión)
```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

### 4. Iniciar el Pipeline Online (Dashboard Seguro en Streamlit)
```powershell
# Opcional: definir credenciales en variables de entorno
$env:IOT_ADMIN_USER="analista_unab"
$env:IOT_DASHBOARD_SECRET="demo-jwt-key-2026"
.\venv\Scripts\streamlit.exe run app/app.py
```
