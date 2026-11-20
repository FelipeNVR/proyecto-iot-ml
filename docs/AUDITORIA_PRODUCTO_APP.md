# 🔍 Auditoría Técnica y de Producto — Consola IoT IPS (`app/app.py`)

**Fecha:** 20 de noviembre de 2026  
**Alcance auditado:** `proyecto-iot-ml/app/app.py`, `src/streaming/`, `src/models/` y flujo de operación para usuarios finales y analistas.

---

## 1. Resumen Ejecutivo

El prototipo cuenta con una base científica y de ciberseguridad sólida (protocolo ciego `6/2/1`, 3 anillos defensivos, verificación `SHA-256`, JWT `HS256`, SQLite parametrizado y 20 pruebas unitarias). Sin embargo, la auditoría de la interfaz anterior identificó **brechas de experiencia de usuario (UX), rendimiento de E/S, higiene de código y endurecimiento de seguridad** necesarias para pasar de una demo técnica a un producto viable, minimalista e intuitivo.

---

## 2. Hallazgos de la Auditoría (Clasificados por Severidad)

| ID | Área | Severidad | Hallazgo Detectado | Acción Tomada (Hoy) / Plan Lanzamiento |
| :-: | :--- | :---: | :--- | :--- |
| **A1** | **UX / Producto** | 🔴 Alta | **Sobrecarga cognitiva ("muro vertical"):** Todo el contenido (controles, alertas, 9 dispositivos, SQL, extractor y 73 experimentos) estaba apilado en una sola vista con jerga cruda y exceso de emojis típicos de apps generadas por IA. | **Resuelto hoy:** Rediseño minimalista profesional en **4 pestañas** (`Resumen de Red`, `Monitor y Forense`, `Auditoría Científica`, `Motor Edge y Seguridad`), tarjetas 3×3 por dispositivo y traductor automático de Z-Score a lenguaje simple. |
| **A2** | **Seguridad** | 🔴 Alta | **Ausencia de protección contra fuerza bruta en login y credenciales demo en código:** `app/app.py` no limitaba intentos fallidos consecutivos y mantiene defaults locales si faltan variables de entorno. | **Mitigado hoy + Roadmap:** Se añadió **rate limiting** en sesión (bloqueo temporal tras 5 intentos fallidos) y aviso explícito si se usan credenciales por defecto. Para lanzamiento real: hashing `Argon2id`, gestor de secretos y TLS obligatorio. |
| **A3** | **Seguridad / Higiene** | 🟠 Media | **Import innecesario (`subprocess`) y rutas locales absolutas (`file:///C:/Users/felip/...`):** `subprocess` no se usaba (alerta en escáneres SAST como `bandit`) y las rutas absolutas se rompen al ejecutar en otro equipo. | **Resuelto hoy:** Se eliminó `import subprocess` y se reemplazaron todas las rutas absolutas por rutas relativas portables. |
| **A4** | **Rendimiento** | 🟠 Media | **Lecturas repetidas a disco en cada `st.rerun()`:** `baseline_metrics.json` y `experiments/rigorous_v1/summary.csv` se leían en cada refresco, e `IncidentStore()` se reinstanciaba en cada ciclo. | **Resuelto hoy:** Lecturas JSON/CSV cacheadas con `@st.cache_data` y carga de `IncidentStore` optimizada. |
| **A5** | **Operabilidad** | 🟡 Media | **Falta de exportación forense y control manual por tarjeta:** El analista no podía descargar el registro de incidentes ni aislar/liberar nodos directamente desde su vista de estado. | **Resuelto hoy:** Botón de descarga **CSV** de incidentes SQLite, acciones rápidas por dispositivo y filtro interactivo en los 73 experimentos. |
| **A6** | **Arquitectura Real** | 🔴 Crítica (2027) | **Acoplamiento UI + Motor de Inferencia:** En Streamlit, `time.sleep() + st.rerun()` bloquea el hilo durante monitoreo continuo y no sirve para captura 24/7. | **Planificado (Sprint 4–5 / 2027):** Desacoplar backend de captura en un demonio independiente (`FastAPI` / `asyncio` + `libpcap`) sirviendo eventos vía WebSocket a la interfaz web. |
| **A7** | **Motor Edge** | 🔴 Crítica (2027) | **Equivalencia numérica y poda de memoria del extractor $O(1)$:** `LiveAfterImageExtractor` necesita certificación decimal contra Kitsune y *garbage collection* de tablas hash para no consumir RAM infinita 24/7. | **Planificado (Sprint 5 / 2027):** Suite de certificación contra `.pcap` de referencia + política LRU/TTL para expirar flujos inactivos. |

---

## 3. Propuestas de Innovación para Diferenciar el Producto (Más allá de un proyecto común)

1. **Explicabilidad en Dos Niveles (Implementado hoy):**
   - *Nivel Usuario:* Traduce automáticamente las métricas matemáticas (`HpHp_L0.01_weight`, `MI_dir_L0.1_mean`, etc.) a alertas comprensibles (*"Ráfaga anormal de conexiones salientes — posible ataque de saturación DDoS"*).
   - *Nivel Analista:* Mantiene el detalle técnico exacto (Z-Score por variable, fold ciego `device_X_rf`, firma del Anillo 2 y verificación del Anillo 3).
2. **Transparencia de Integridad MLOps en Vivo (Implementado hoy):**
   - Panel dedicado en la pestaña **Motor Edge y Seguridad** que muestra el estado criptográfico `SHA-256` real de los artefactos verificados en memoria.
3. **Siguiente Salto de Producto (Opcional para fase Edge 2027):**
   - **Alertas instantáneas por Telegram/Webhook** al detectar el primer nodo anómalo (sin que el dueño tenga que mirar el dashboard).
   - **Cuarentena con Rollback Automático (`TTL = 15 min`):** Si un bloqueo automático en OpenWrt fue falso positivo, se revierte solo o se aprueba con un clic desde el celular.
   - **Perfilado Automático ("Modo Aprendizaje 24h"):** Al conectar una cámara nueva en casa, el sistema observa 24 horas de tráfico legítimo para calibrar su propio umbral sin intervención técnica.
