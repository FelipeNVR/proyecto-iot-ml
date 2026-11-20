# 🔄 Planificación y Gestión Ágil con Metodología Scrum
## Proyecto: Sistema Centralizado de Detección de Anomalías en Redes IoT mediante Machine Learning (CINF200)

- **Estudiante (Scrum Master & Developer):** Felipe Nicolás Vergara Rodríguez
- **Docente Guía (Product Owner / Stakeholder Técnico):** Nicolás Caselli Benavente
- **Asignatura:** CINF200 — Seminario de Licenciatura en Ciencias de la Ingeniería (UNAB)
- **Horizonte del Proyecto:** Semestre 2026-2 (Sprints 1, 2 y 3) + Continuidad 2027-1 (Sprints 4, 5, 6 y 7)

---

## 1. Adaptación del Marco Scrum al Proyecto

Dado que el proyecto combina investigación aplicada en **Machine Learning (Pipeline Offline)** con el desarrollo de software de ciberseguridad (**Consola MVP en Streamlit — Pipeline Online**), se adoptó una adaptación de **Scrum Académico Iterativo e Incremental**, estructurada en Sprints de **3 a 4 semanas** alineados con los hitos de evaluación de la asignatura y las 11 etapas del plan anual.

### 1.1 Roles del Equipo Scrum
| Rol Scrum | Responsable | Responsabilidades en el Proyecto |
| :--- | :--- | :--- |
| **Product Owner (PO)** | **Prof. Nicolás Caselli Benavente** | Define la visión académica y técnica del producto, prioriza los requisitos de rigor metodológico (ej. auditoría anti-fuga, separación de roles 6/2/1, arquitectura de doble pipeline) y aprueba los incrementos en cada *Sprint Review*. |
| **Scrum Master (SM)** | **Felipe Vergara Rodríguez** | Gestiona el tablero de trabajo, controla el cumplimiento de la *Definition of Done (DoD)*, identifica y remueve impedimentos técnicos (ej. contaminación de timestamps Unix 2017 en `HH_jit`, sobrecarga de memoria RAM al leer 7M de filas). |
| **Development Team** | **Felipe Vergara Rodríguez** | Diseña la arquitectura, programa los módulos de datos (`preprocess.py`), modelamiento (`baseline.py`, `rigorous.py`), streaming e IPS (`app.py`, `firewall_controller.py`, `incident_store.py`), ejecuta las 20 pruebas unitarias y redacta la documentación en LaTeX. |

### 1.2 Ceremonias Aplicadas
1. **Sprint Planning (Inicio de cada Sprint):** Selección de Historias de Usuario (HU) desde el *Product Backlog*, estimación en Puntos de Historia (*Story Points* en escala Fibonacci: `1, 2, 3, 5, 8, 13`) y definición del *Sprint Goal*.
2. **Seguimiento Semanal con Tutor (Weekly Sync):** Revisión de avances, inspección de métricas experimentales y ajuste de criterios técnicos junto al profesor guía.
3. **Sprint Review (Cierre de Hito):** Demostración funcional del incremento (notebook, experimentos reproducibles y prototipo MVP en vivo en `localhost:8501`).
4. **Sprint Retrospective:** Análisis crítico de lo realizado para detectar oportunidades de mejora metodológica antes del siguiente Sprint.

### 1.3 Definición de Terminado (*Definition of Done — DoD*)
Ninguna Historia de Usuario se considera **Completada (*Done*)** si no cumple simultáneamente:
- [x] Código modular en Python 3.13 versionado y subido a GitHub (`origin/main`).
- [x] Ausencia verificada de fuga de datos (*data leakage*) entre entrenamiento, calibración y prueba.
- [x] Artefactos `.pkl`/`.joblib` firmados y verificados con hash criptográfico `SHA-256`.
- [x] Suite de pruebas automatizadas (`unittest`) pasando al 100% sin errores (`20/20 tests OK`).
- [x] Documentación técnica sincronizada con el informe oficial (`main.tex`).

---

## 2. Resumen Ejecutivo del Estado de los Sprints

| Sprint | Periodo | Etapas del Informe | Objetivo Principal (*Sprint Goal*) | Puntos (SP) | Estado Actual |
| :--- | :--- | :---: | :--- | :---: | :---: |
| **Sprint 1** | Semanas 7 a 10 (2026-2) | Etapas 1 y 2 (Hito E1) | Formulación, auditoría de los 89 CSV (7M filas) y pipeline de limpieza y sanitización. | **21 SP** | ✅ **COMPLETADO** |
| **Sprint 2** | Semanas 11 a 14 (2026-2) | Etapas 3, 4, 5 y 6 (Hito E2) | Entrenamiento 3 Anillos, Protocolo Ciego 6/2/1 (73 exp.) y MVP Streamlit + Firewall + SQLite. | **34 SP** | ✅ **COMPLETADO** |
| **Sprint 3** | Semanas 15 a 18 (2026-2) | Etapa 7 y Cierre (Hito E3) | Integración feedback E2 (CRISP-DM / CRISP-ML(Q)), Paper Final (11 secc.), Póster A0, Portafolio y Defensa E3. | **21 SP** | ✅ **COMPLETADO (E3)** |
| **Sprint 4** | Marzo – Abril 2027 (2027-1) | Etapa 8 | Portabilidad del motor ML y folds ciegos a microordenador de borde (*Edge / Raspberry Pi*). | **18 SP** | 📅 **PLANIFICADO (2027-1)** |
| **Sprint 5** | Abril – Mayo 2027 (2027-1) | Etapa 9 | Capturador de paquetes en tiempo real (`libpcap` / *Port Mirroring*) e integración del extractor $O(1)$. | **21 SP** | 📅 **PLANIFICADO (2027-1)** |
| **Sprint 6** | Mayo – Junio 2027 (2027-1) | Etapa 10 | Pruebas prolongadas en red doméstica real (medición de FPR en uso cotidiano) y bloqueo IPS activo. | **21 SP** | 📅 **PLANIFICADO (2027-1)** |
| **Sprint 7** | Junio – Julio 2027 (2027-1) | Etapa 11 | Exploración de *Autoencoder* profundo liviano para ataques *Zero-Day* y cierre anual. | **18 SP** | 📅 **PLANIFICADO (2027-1)** |

---

## 3. Detalle de Sprints Realizados y por Realizar (Semestre 2026-2)

---

### ✅ SPRINT 1: Fundamentos, Auditoría de Datos y Preprocesamiento (COMPLETADO)
- **Duración:** Semanas 7 a 10 (Septiembre – mediados de Octubre 2026)
- **Correspondencia con el Informe:** Hito E1 + Etapa 1 y Etapa 2
- **Sprint Goal:** *Establecer la brecha científica frente al estado del arte, auditar la integridad del dataset UCI N-BaIoT completo y construir el módulo de ingesta y sanitización sin fuga temporal.*

#### Backlog del Sprint 1 (21 Story Points completados)
| ID | Historia de Usuario (Formato Ágil) | Criterio de Aceptación / Evidencia | SP | Estado |
| :--- | :--- | :--- | :---: | :---: |
| **HU-01** | **Como** investigador, **quiero** analizar críticamente el estado del arte en detección de botnets IoT **para** definir la brecha de transferencia a dispositivos no vistos y los criterios de éxito ($F1 \ge 0.95$, $\text{FPR} \le 1\%$, $\le 10$ ms). | Tablas de Estado del Arte, Criterios de Éxito, Requisitos (`RF-01` a `RNF-04`) y Matriz de Riesgos aprobados en E1. | 5 | ✅ Hecho |
| **HU-02** | **Como** científico de datos, **quiero** inspeccionar los 89 archivos CSV reales de los 9 dispositivos N-BaIoT **para** verificar tipos de datos, balance de clases y ausencia de valores corruptos (`NaN`/`Inf`). | Escaneo completo de `7.062.606` filas (`555.932` benignas y `6.506.674` de ataque) con `0` valores no finitos + `01_exploracion_dataset.ipynb`. | 5 | ✅ Hecho |
| **HU-03** | **Como** ingeniero de ML, **quiero** detectar y neutralizar columnas con artefactos de laboratorio en el extractor Kitsune **para** evitar que los árboles memoricen la fecha de captura en lugar del tráfico físico. | Función `sanitize_jitter_features()` en `src/data/preprocess.py` que neutraliza media/varianza de `HH_jit` (época Unix 2017) preservando los conteos `HH_jit_*_weight`. | 8 | ✅ Hecho |
| **HU-04** | **Como** ingeniero de datos, **quiero** particionar secuencialmente cada captura y ajustar el `StandardScaler` solo sobre entrenamiento **para** prevenir fuga estadística antes de modelar. | Funciones `chronological_split()` (65/15/15 con 2.5% de purga) y generación del catálogo de prueba `stream_sample_real.csv`. | 3 | ✅ Hecho |

- **Retrospectiva del Sprint 1:**
  - *¿Qué salió bien?* Se logró procesar un dataset masivo de más de 7 millones de registros en un computador local mediante muestreo estructurado por bloques sin agotar la memoria RAM.
  - *Hallazgo clave para el Sprint 2:* Se descubrió que evaluar solo con particiones convencionales dentro de los mismos dispositivos produce métricas cercanas al 100%, por lo que en el Sprint 2 se decidió diseñar un protocolo mucho más exigente separando dispositivos de ajuste, calibración y prueba.

---

### ✅ SPRINT 2: Modelamiento en 3 Anillos, Protocolo 6/2/1 y MVP Operativo (COMPLETADO)
- **Duración:** Semanas 11 a 14 (Mediados de Octubre – 02 de Noviembre 2026)
- **Correspondencia con el Informe:** Hito E2 + Etapas 3, 4, 5 y 6
- **Sprint Goal:** *Entrenar y auditar los modelos supervisados y no supervisados bajo el protocolo riguroso 6/2/1 (73 experimentos) y construir el Dashboard MVP en Streamlit con autenticación JWT, persistencia SQLite, Paciente Cero, reglas de Firewall y enrutamiento ciego por dispositivo.*

#### Backlog del Sprint 2 (34 Story Points completados)
| ID | Historia de Usuario (Formato Ágil) | Criterio de Aceptación / Evidencia | SP | Estado |
| :--- | :--- | :--- | :---: | :---: |
| **HU-05** | **Como** ingeniero de ML, **quiero** entrenar una línea base (`Dummy` + `Regresión Logística`) y compararla contra `Random Forest`, `Gradient Boosting`, `SVM` y `Árbol de Decisión` **para** seleccionar el clasificador con mejor relación F1/FPR/latencia. | `src/models/baseline.py` ejecutado; artefactos en `models_registry/` y métricas en `baseline_metrics.json` y `lodo_metrics.json`. | 5 | ✅ Hecho |
| **HU-06** | **Como** auditor de ML, **quiero** implementar un protocolo riguroso `6/2/1` con 6 bloques por archivo y exclusión total de familias (`Mirai` vs `BASHLITE`) **para** medir la capacidad real de generalización y sus caídas ante ataques *Zero-Day*. | `src/models/rigorous.py` y `experiments/rigorous_v1/` con **73 experimentos**, ablaciones y 9 modelos ciegos en rotación (`device_1_rf` a `device_9_rf`). | 8 | ✅ Hecho |
| **HU-07** | **Como** arquitecto de ciberseguridad, **quiero** integrar un Anillo 2 Multiclase (10 subtipos de botnet) y un Anillo 3 No Supervisado (`LocalOutlierFactor`) **para** identificar la firma del ataque y contener variantes desconocidas. | `model_multiclass_attack.pkl` (91.76% accuracy canónica) y `model_zeroday_iforest.pkl` (75.6% recall entrenado 100% con tráfico benigno). | 5 | ✅ Hecho |
| **HU-08** | **Como** analista SOC, **quiero** una consola web en Streamlit protegida con login JWT (`HS256`) y verificación `SHA-256` que permita inyectar ataques reales por dispositivo usando su Fold Ciego `6/2/1` **para** auditar la detección en vivo sin trampa. | `app/app.py` con toggle `🔬 Evaluación Ciega 6/2/1`, verificador `verify_file_sha256()` y explicabilidad local `Z-Score`. | 8 | ✅ Hecho |
| **HU-09** | **Como** administrador de red, **quiero** que el sistema identifique al *Paciente Cero* en SQLite y genere reglas de cortafuegos (`iptables`/`nftables`) con candado IP+MAC y *Whitelist Anti-Lockout* **para** aislar al nodo atacante sin bloquear el router. | `src/streaming/incident_store.py` (SQL parametrizado) y `src/streaming/firewall_controller.py`. | 5 | ✅ Hecho |
| **HU-10** | **Como** desarrollador, **quiero** una suite de pruebas automatizadas que valide particiones, no-fuga, umbrales, SQLite y esquemas de reporte **para** asegurar la calidad antes de cada `git push`. | 20 pruebas unitarias en `tests/` (`test_pipeline.py`, `test_rigorous.py`, `test_reporting.py`) pasando en `0.35 s`. | 3 | ✅ Hecho |

- **Retrospectiva del Sprint 2:**
  - *¿Qué salió bien?* Se superó el alcance básico al implementar los 73 experimentos del protocolo 6/2/1 y conectar los 9 folds ciegos directamente al inyector de ataques del Dashboard.
  - *Impedimento resuelto:* Se detectó que si el inyector en vivo usaba un único modelo estático, este ya conocería al menos a 6 u 8 dispositivos del entrenamiento. Se resolvió enrutando dinámicamente cada dispositivo $X$ a su candidato excluido `device_X_rf` (`0%` visto en entrenamiento y calibración).

---

### ✅ SPRINT 3: Consolidación Científica, Paper Final, Póster y Defensa (COMPLETADO — HITO E3)
- **Duración:** Semanas 15 a 18 (03 de Noviembre – 28 de Noviembre 2026)
- **Correspondencia con el Informe:** Hito E3 (45% de ponderación) + Etapa 7 y Cierre del Semestre 2026-2
- **Sprint Goal:** *Incorporar la retroalimentación del profesor guía en el Hito E2 (Metodología Híbrida CRISP-DM / CRISP-ML(Q) + Scrum), profundizar la discusión crítica y limitaciones, finalizar el informe en formato artículo científico (paper), y preparar el póster académico, el portafolio y la defensa final.*

#### Backlog del Sprint 3 (21 Story Points completados)
| ID | Historia de Usuario (Formato Ágil) | Criterio de Aceptación / Entregable | SP | Estado |
| :--- | :--- | :--- | :---: | :---: |
| **HU-11** | **Como** autor del proyecto, **quiero** integrar el feedback del profesor guía en E2 incorporando la metodología híbrida **CRISP-DM / CRISP-ML(Q) + Scrum** **para** articular el rigor de ciencia de datos con la gestión ágil. | Sección 5.1 (`main.tex`), citas formales en `references.bib` y registro en `FEEDBACK_PROFESOR_E2_Y_METODOLOGIA.md`. | 5 | ✅ Hecho |
| **HU-12** | **Como** investigador, **quiero** consolidar el Paper Final E3 con las 11 secciones exactas de la plantilla (Evaluación, Discusión crítica, Conclusiones y Anexos A, B y C) **para** cumplir el 100% de la rúbrica E3. | Informe final `main.tex` verificado (Abstract 205 palabras, 10 referencias todas citadas, figuras 300 DPI y Anexos A–C). | 8 | ✅ Hecho |
| **HU-13** | **Como** expositor, **quiero** diseñar el Póster Científico A0 y estructurar el Portafolio mínimo de 10 evidencias **para** comunicar visualmente el proyecto y garantizar trazabilidad institucional. | `poster_E3.tex` (formato A0, 3 columnas, 5 figuras) + `PORTAFOLIO_E3_CINF200.md`. | 5 | ✅ Hecho |
| **HU-14** | **Como** candidato a la licenciatura, **quiero** preparar la presentación final Beamer y el guión de defensa oral con preguntas de comisión **para** defender con solvencia el proyecto en Semana 17. | `presentacion_E3.tex` (16 láminas) + `GUION_DEFENSA_FINAL_E3.md`. | 3 | ✅ Hecho |

---

## 4. Product Backlog de Continuidad para el Próximo Año (Semestre 2027-1)

Siguiendo la planificación de continuidad a un año (Sección 6.4 del informe, **Etapas 8 a 11**), el desarrollo del primer semestre de 2027 (Marzo a Julio) se divide en **4 Sprints de validación en hardware y red real**:

---

### 📅 SPRINT 4: Despliegue en Hardware de Borde — *Edge Computing* (Marzo – Abril 2027)
- **Correspondencia:** Etapa 8 del Plan de Trabajo.
- **Sprint Goal:** *Portar el motor de inferencia de 3 anillos y los artefactos serializados a un microordenador de bajo costo (Raspberry Pi 4/5 o gateway Linux embebido), midiendo consumo real de CPU, RAM y temperatura.*
- **Historias de Usuario Clave (18 SP):**
  - **HU-15 (8 SP):** Empaquetar el motor de inferencia y verificación `SHA-256` como servicio ligero de sistema (`systemd` / contenedor Docker ARM64) en Raspberry Pi.
  - **HU-16 (5 SP):** Ejecutar benchmark comparativo de latencia por paquete y huella de memoria RAM en arquitectura ARM frente a CPU de escritorio.
  - **HU-17 (5 SP):** Configurar interfaz de red secundaria en modo promiscuo / *bridge* para recepción pasiva de tramas locales.

---

### 📅 SPRINT 5: Captura de Tráfico en Vivo y Equivalencia del Extractor $O(1)$ (Abril – Mayo 2027)
- **Correspondencia:** Etapa 9 del Plan de Trabajo.
- **Sprint Goal:** *Conectar el capturador de paquetes en tiempo real (`libpcap` / `Scapy` / `NFStream`) al extractor incremental `LiveAfterImageExtractor` y certificar su equivalencia numérica frente al extractor original Kitsune.*
- **Historias de Usuario Clave (21 SP):**
  - **HU-18 (8 SP):** Certificar matemáticamente que `src/streaming/live_feature_extractor.py` reproduzca las 115 estadísticas de decaimiento exponencial ($\lambda \in \{5, 3, 1, 0.1, 0.01\}$) sobre archivos `.pcap` de referencia sin deriva numérica.
  - **HU-19 (8 SP):** Implementar control de expiración y poda de memoria (*garbage collection* de flujos inactivos en las tablas hash) para operación continua 24/7 sin fugas de RAM.
  - **HU-20 (5 SP):** Conectar el flujo de paquetes capturados de una cámara IP física de prueba hacia el pipeline online en vivo.

---

### 📅 SPRINT 6: Pruebas de Estrés en Red Doméstica Real y Mitigación Activa (Mayo – Junio 2027)
- **Correspondencia:** Etapa 10 del Plan de Trabajo.
- **Sprint Goal:** *Evaluar la tasa real de falsas alarmas (FPR por día) bajo tráfico doméstico cotidiano intenso y validar la ejecución efectiva de las reglas de aislamiento en un router con OpenWrt/Linux.*
- **Historias de Usuario Clave (21 SP):**
  - **HU-21 (8 SP):** Ejecutar sesiones de monitoreo continuo de 7 días con tráfico legítimo de alta carga (streaming 4K, videollamadas WebRTC, videojuegos online y cámaras HD) para medir y recalibrar la tasa de falsos positivos operacional.
  - **HU-22 (8 SP):** Integrar la ejecución real y reversión segura (*rollback* automático con temporizador) de los comandos `iptables`, `nftables` y `conntrack` en un router/gateway con firmware OpenWrt.
  - **HU-23 (5 SP):** Auditar la resistencia del candado Capa 2/Capa 3 (`IP + MAC`) y la *Lista Blanca Anti-Lockout* en pruebas controladas de suplantación de IP (*IP-Spoofing*) en laboratorio.

---

### 📅 SPRINT 7: Exploración de Autoencoder Liviano para *Zero-Day* y Cierre Anual (Junio – Julio 2027)
- **Correspondencia:** Etapa 11 del Plan de Trabajo.
- **Sprint Goal:** *Implementar y comparar un Autoencoder ligero no supervisado como evolución del Anillo 3 para mejorar la detección de familias de botnets inéditas (donde los clasificadores supervisados cayeron a 39.9%–48.5% de recall) y consolidar la publicación final.*
- **Historias de Usuario Clave (18 SP):**
  - **HU-24 (8 SP):** Entrenar un *Autoencoder* compacto (cuantizado para CPU de borde) exclusivamente sobre tráfico benigno de múltiples días y compararlo contra `LocalOutlierFactor` y `Random Forest` en el escenario de exclusión total de familias (`Mirai` vs `BASHLITE`).
  - **HU-25 (5 SP):** Integrar el ensamble híbrido final (Árboles Supervisados + Autoencoder/LOF) en la consola de monitoreo.
  - **HU-26 (5 SP):** Redactar el informe de cierre de continuidad 2027-1 y liberar la versión final de código abierto documentada.

---

## 5. Tablero Kanban Actual del Proyecto (Al 19 de Noviembre de 2026 — Cierre E3)

| 📋 Por Hacer (*To Do* — Continuidad 2027-1) | 🔄 En Progreso (*In Progress* — Defensa Semana 17) | ✅ Terminado (*Done* — Sprints 1, 2 y 3) |
| :--- | :--- | :--- |
| • **Sprints 4 a 7 (2027-1):** Edge Raspberry Pi (Etapa 8), captura PCAP en vivo y certificación del extractor $O(1)$ (Etapa 9), pruebas FPR domésticas en OpenWrt (Etapa 10) y Autoencoder liviano para Zero-Day (Etapa 11). | • Defensa oral final del **Hito E3 (45%)** y demostración en vivo en `http://localhost:8501` (Semana 17: 23–28 nov.). | • **HU-01 a HU-04 (Sprint 1):** Estado del arte, escaneo de 89 CSV (`7.062.606` filas), sanitización `HH_jit` y partición temporal.<br>• **HU-05 a HU-10 (Sprint 2):** 3 Anillos entrenados, **73 experimentos** del Protocolo `6/2/1`, 9 Folds Ciegos conectados al Dashboard, Paciente Cero en SQLite, generador `iptables`/`nftables`, `SHA-256`, `JWT HS256` y **20 tests unitarios en verde**.<br>• **HU-11 a HU-14 (Sprint 3):** Metodología híbrida **CRISP-DM / CRISP-ML(Q) + Scrum**, Paper Final (`main.tex`, 11 secciones + Anexos A–C), Póster A0 (`poster_E3.tex`), Presentación Final (`presentacion_E3.tex`), Guión E3 y Portafolio (`PORTAFOLIO_E3_CINF200.md`). |
