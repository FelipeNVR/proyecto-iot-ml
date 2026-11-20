# 📋 Registro de Feedback del Profesor Guía (Hito E2) y Propuesta Metodológica Dual

- **Fecha del Hito E2:** 2 de noviembre de 2026
- **Estudiante:** Felipe Nicolás Vergara Rodríguez
- **Profesor Guía:** Nicolás Caselli Benavente
- **Estado de la Presentación E2:** Realizada con éxito (pendiente publicación de nota oficial).

---

## 1. Feedback Recibido del Profesor en la Defensa E2

1. **Valoración General:** La metodología experimental presentada (saneamiento de fuga temporal `HH_jit`, protocolo riguroso `6/2/1` con 9 modelos en rotación ciega, pruebas Zero-Day y defensa en 3 anillos) **está bien planteada y sólida**.
2. **Oportunidad de Mejora / Complemento (Hacia E3):**
   - El profesor sugirió **complementar la metodología actual con una segunda metodología formal**, recomendando específicamente **CRISP-DM** (*Cross-Industry Standard Process for Data Mining*), de modo que el proyecto no solo tenga una estructura de gestión/desarrollo o validación experimental aislada, sino un marco metodológico estándar completo.

---

## 2. Análisis Técnico: ¿Qué opinamos de CRISP-DM y cuál es la mejor combinación para nuestro proyecto?

### ¿Por qué el profesor te recomendó CRISP-DM?
Porque en proyectos de Ingeniería Civil Informática que tienen tanto **Ciencia de Datos / Machine Learning** como **Desarrollo de Software (MVP)**, una sola metodología queda coja:
- Si usas solo **Scrum**, explicas muy bien *cómo organizaste las semanas, los Sprints y el desarrollo del Dashboard*, pero Scrum no dice nada sobre cómo limpiar datos, evitar el *Data Leakage* o calibrar umbrales de falsos positivos.
- Si usas solo un **protocolo experimental de ML**, explicas las pruebas matemáticas, pero falta el marco estándar de la industria.

### Comparativa de Opciones para tu Proyecto IoT

| Metodología | Enfoque Principal | Lo mejor para tu proyecto | Lo que le falta si se usa sola |
| :--- | :--- | :--- | :--- |
| **1. CRISP-DM (Clásica, 1999)** | Ciclo de vida de minería de datos en 6 fases iterativas. | Es el estándar más conocido por las comisiones académicas y el profesor te la pidió directamente. Calza 1 a 1 con tus etapas de datos y modelado. | Fue creada en 1999: no incluye explícitamente *Quality Assurance* contra fuga de datos (*data leakage*), seguridad MLOps (`SHA-256`) ni gestión ágil de software. |
| **2. CRISP-ML(Q) (Studer et al., 2021)** | Evolución moderna de CRISP-DM para **Machine Learning con Aseguramiento de Calidad (Quality Assurance)**. | **Es la más precisa técnicamente para lo que hiciste:** exige auditar sesgos/fugas en los datos (`HH_jit`), probar robustez ante cambios de distribución (*Zero-Day*), firmar modelos (`SHA-256`) y monitorear en vivo. | Menos conocida por nombre que CRISP-DM tradicional si no se menciona que es su extensión directa. |
| **3. Scrum (Ágil)** | Gestión iterativa del proyecto y construcción incremental del software MVP. | Ordena el plan de trabajo en Sprints, define *Product Backlog*, *Definition of Done (DoD)* y entregas funcionales del Dashboard + Firewall. | No estructura las fases matemáticas del entrenamiento ni la evaluación estadística `6/2/1`. |

---

## 3. Recomendación Ganadora para la Entrega Final (E3): Metodología Híbrida Dual

La mejor decisión estratégica —porque **le hace caso 100% al profesor con CRISP-DM**, mantiene **Scrum** y además agrega el toque de excelencia de **CRISP-ML(Q)**— es declarar una **Metodología Híbrida de Doble Capa**:

1. **Capa de Ciencia de Datos e IA $\to$ CRISP-DM + Extensión de Calidad CRISP-ML(Q):**
   Gobierna todo el flujo técnico de los datos y modelos en sus 6 fases clásicas, añadiendo el sello de aseguramiento de calidad (`Q`):
   - **Fase 1 — Comprensión del Negocio/Red IoT:** Restricciones de CPU/RAM en nodos IoT, necesidad de defensa perimetral en el Router/Gateway y metas operativas ($F1 \ge 0.95$, $\text{FPR} \le 1\%$, latencia $\le 10\text{ ms}$).
   - **Fase 2 — Comprensión de los Datos:** Auditoría exhaustiva de los 89 CSV (7.062.606 filas, 0 NaN/Inf) y **detección de la fuga del reloj Unix 2017 en `HH_jit_*_mean`**.
   - **Fase 3 — Preparación de los Datos:** Sanitización a `0.0` de la media/varianza de `HH_jit`, extracción por 6 bloques posicionales disjuntos ($10\%, 30\%, 50\%, 65\%, 80\%, 95\%$) y escalamiento sin contaminación.
   - **Fase 4 — Modelado:** Construcción de la arquitectura defensiva en **3 Anillos** (Anillo 1: 9 modelos Random Forest en rotación ciega `device_1_rf` a `device_9_rf`; Anillo 2: clasificador multiclase de 10 ataques; Anillo 3: detector no supervisado `LOF`).
   - **Fase 5 — Evaluación (Aseguramiento de Calidad CRISP-ML(Q)):** Contraste con línea base (`DummyClassifier`), protocolo histórico LODO `8/1` y protocolo riguroso `6/2/1` (73 experimentos, calibración de umbral $\text{FPR} \le 0.1\%$, ablación de variables y prueba de fuego *Zero-Day*).
   - **Fase 6 — Despliegue y Monitoreo:** Consola SOC en Streamlit con enrutamiento ciego en vivo, identificación de **Paciente Cero** en SQLite, reglas `iptables`/`nftables` con lista blanca, autenticación JWT y verificación criptográfica `SHA-256`.

2. **Capa de Gestión y Desarrollo de Software $\to$ Scrum Adaptado (Sprints):**
   Gobierna la planificación temporal, el control de avances (Sprints 1, 2 y 3 en 2026-2; Sprints 4 a 7 en 2027-1), los entregables incrementales y la matriz de riesgos.

---

## 4. Mapa de Integración: Cómo encajan CRISP-DM + Scrum en tu Proyecto

```
+-----------------------------------------------------------------------------------+
|                   MARCO DE GESTIÓN ÁGIL: SCRUM (Sprints 1 al 7)                   |
|   Planificación Semanal · Product Backlog · Gestión de Riesgos · 20 Tests (DoD)   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|          CICLO DE VIDA CIENTÍFICO DE IA: CRISP-DM + Calidad CRISP-ML(Q)           |
|                                                                                   |
|  [1. Comprensión Red IoT] ---> [2. Auditoría N-BaIoT (Hallazgo HH_jit Unix)]      |
|             ^                                       |                             |
|             |                                       v                             |
|  [6. Despliegue MVP + SOC] <-- [5. Evaluación 6/2/1] <-- [3. Sanitización 6 Bloq] |
|   (JWT, SHA-256, Firewall)      (73 Exp + Zero-Day)              |                |
|                                         ^                        v                |
|                                         +--------- [4. Modelado 3 Anillos]        |
+-----------------------------------------------------------------------------------+
```
