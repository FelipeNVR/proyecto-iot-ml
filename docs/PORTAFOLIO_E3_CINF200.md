# 📁 Portafolio Mínimo de Evidencias — Entrega Final E3 (CINF200)

- **Proyecto:** Sistema Centralizado de Detección de Anomalías en Redes IoT mediante Machine Learning
- **Estudiante:** Felipe Nicolás Vergara Rodríguez
- **Profesor Guía:** Nicolás Caselli Benavente
- **Asignatura:** CINF200 — Integrador II: Seminario de Licenciatura en Ciencias de la Ingeniería (UNAB, Viña del Mar, 2026-2)
- **Repositorio Público:** <https://github.com/FelipeNVR/proyecto-iot-ml>

---

## 1. Matriz de Cumplimiento del Portafolio Mínimo (Syllabus Oficial CINF200)

| # | Evidencia Obligatoria del Syllabus | Ubicación / Archivo Verificable | Estado |
| :-: | :--- | :--- | :---: |
| **1** | **Ficha de proyecto y diagnóstico inicial** | `main.tex` (Secciones 1, 2 y 3) y `Contexto_Proyecto_IoT.md` | ✅ Completo |
| **2** | **Matriz de fuentes y estado del arte** | `main.tex` (Sección 4, Tabla 1: 6 estudios 2018–2026) y `references.bib` (10 referencias IEEE) | ✅ Completo |
| **3** | **Plan de trabajo actualizado** | `main.tex` (Sección 6.4: Etapas 1–7 2026-2 + Continuidad 8–11 2027-1 + Cartas Gantt) y `METODOLOGIA_SCRUM_PROYECTO.md` (Sprints 1–7) | ✅ Completo |
| **4** | **Diseño metodológico y arquitectura** | `main.tex` (Sección 5: Metodología Híbrida CRISP-DM / CRISP-ML(Q) + Scrum; Sección 7: Arquitectura Doble Pipeline, 3 Anillos y 7 ADRs) y `FEEDBACK_PROFESOR_E2_Y_METODOLOGIA.md` | ✅ Completo |
| **5** | **Código, prototipo y MVP técnico** | `proyecto-iot-ml/` (`src/data/preprocess.py`, `src/models/baseline.py`, `src/models/rigorous.py`, `src/streaming/device_onboarding.py`, `app/app.py`) | ✅ Completo |
| **6** | **Pruebas y resultados reproducibles** | `proyecto-iot-ml/experiments/rigorous_v1/` (**73 experimentos**, `summary.csv`, `RESULTADOS.md`), `models_registry/` y `tests/` (**25/25 tests OK**) | ✅ Completo |
| **7** | **Paper final (Formato IEEE/UNAB)** | `main.tex` (11 secciones + Referencias + Anexos A, B y C) + figuras 300 DPI | ✅ Completo |
| **8** | **Póster académico** | `poster_E3.tex` (Formato A0 vertical en 3 columnas con 5 figuras y KPIs) | ✅ Completo |
| **9** | **Presentación final y guión de defensa** | `presentacion_E3.tex` (Beamer 16:9, 16 láminas) y `GUION_DEFENSA_FINAL_E3.md` | ✅ Completo |
| **10** | **Declaración individual de contribución y uso de IA** | `main.tex` (Anexo A: Declaración de uso de IA; Anexo B: Contribución individual; Anexo C: Evidencias E3) | ✅ Completo |

---

## 2. Verificación de Reproducibilidad del Producto Tecnológico

Desde el directorio `proyecto-iot-ml/`:

```powershell
# 1. Ejecutar la suite completa de 20 pruebas unitarias (contratos, anti-fuga, SQLite, SHA-256, firewall)
.\venv\Scripts\python.exe -m unittest discover -s tests -v

# 2. Levantar el prototipo MVP en navegador local (http://localhost:8501)
.\venv\Scripts\python.exe -m streamlit run app\app.py

# 3. (Opcional) Re-ejecutar una corrida nueva del protocolo riguroso 6/2/1
.\venv\Scripts\python.exe -m src.models.rigorous --output experiments/nueva_corrida
```

---

## 3. Lista de Archivos para Subir a Overleaf (Compilación 100% Limpia)

Para compilar **`main.tex` (Paper Final)**, **`poster_E3.tex` (Póster)** y **`presentacion_E3.tex` (Presentación Final)** en Overleaf, asegúrate de subir en la misma carpeta del proyecto estos archivos:

- Fuentes LaTeX y Bibliografía:
  - `main.tex`
  - `references.bib`
  - `poster_E3.tex`
  - `presentacion_E3.tex`
- Imágenes y Figuras 300 DPI:
  - `logo_ici.png`
  - `fig_ppt_topologia_iot.png`
  - `fig_ppt_importancia_rf.png`
  - `fig_ppt_protocolo_621.png`
  - `fig_ppt_zeroday_caida.png`
  - `dashboard_funcionando.png`
