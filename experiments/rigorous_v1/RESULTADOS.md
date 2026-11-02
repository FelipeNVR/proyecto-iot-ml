# Resultados del protocolo exigente — 1 de noviembre de 2026

**Estado: benchmark de desarrollo; no autorizado para producción.**

Se completaron 73 experimentos con datos reales de laboratorio. Se inspeccionaron 7,062,606 filas en 89 archivos; 0 filas con valores no finitos.

Se conservaron bloques en seis posiciones por captura. El test tardío usa hasta 1.000 benignos y 200 ataques por bloque y archivo. La distribución de clases es la de esta selección, no la prevalencia de una red doméstica.

## Dispositivo externo: seis para ajustar, dos para calibrar y uno para probar

Promedios no ponderados sobre nueve dispositivos. El umbral ajustado busca FPR empírico ≤ 0,1 % en la calibración; el objetivo no garantiza esa tasa fuera de muestra. Se muestra el umbral fijo para distinguir dificultad de datos y efecto del umbral.

| Modelo | Regla | F1 medio | FPR medio | Peor FPR | Menor recall |
|---|---|---:|---:|---:|---:|
| lr | 0,5 | 0.9933 | 2.42% | 16.55% | 99.45% |
| lr | Ajustado | 0.8007 | 0.04% | 0.35% | 22.62% |
| rf | 0,5 | 0.9998 | 0.05% | 0.25% | 99.95% |
| rf | Ajustado | 0.9995 | 0.14% | 0.51% | 99.95% |
| gb | 0,5 | 0.9934 | 1.87% | 9.10% | 99.95% |
| gb | Ajustado | 0.9452 | 2.95% | 16.55% | 60.00% |

## Familia y dispositivo nunca vistos — Random Forest

| Familia excluida | Dispositivo | F1 fijo 0,5 | F1 ajustado | Recall ajustado | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| gafgyt | 1 | 0.7257 | 1.0000 | 100.00% | 0 | 0 |
| mirai | 1 | 0.8907 | 0.8907 | 80.30% | 0 | 394 |
| gafgyt | 2 | 0.7220 | 0.9906 | 100.00% | 38 | 0 |
| mirai | 2 | 0.9455 | 0.9455 | 89.70% | 1 | 206 |
| gafgyt | 3 | 0.7500 | 0.9995 | 99.95% | 1 | 1 |
| gafgyt | 4 | 0.7500 | 0.7500 | 60.00% | 0 | 800 |
| mirai | 4 | 0.5705 | 0.5702 | 39.90% | 1 | 1202 |
| gafgyt | 5 | 0.7500 | 0.7500 | 60.00% | 0 | 800 |
| mirai | 5 | 0.8546 | 0.8433 | 72.90% | 0 | 542 |
| gafgyt | 6 | 0.6518 | 0.6537 | 48.55% | 0 | 1029 |
| mirai | 6 | 0.8735 | 0.8154 | 68.90% | 2 | 622 |
| gafgyt | 7 | 0.6992 | 0.7009 | 53.95% | 0 | 921 |
| gafgyt | 8 | 0.6920 | 0.7500 | 60.00% | 0 | 800 |
| mirai | 8 | 0.8318 | 0.9778 | 100.00% | 91 | 0 |
| gafgyt | 9 | 0.6975 | 0.9973 | 99.95% | 10 | 1 |
| mirai | 9 | 0.8294 | 0.9983 | 100.00% | 7 | 0 |

## Ablaciones predefinidas — Random Forest

Resultados exploratorios. No se seleccionó un ganador para producción mirando estos tests.

| Representación | F1 externo medio ajustado | FPR externo medio | Menor recall |
|---|---:|---:|---:|
| sanitized | 0.9995 | 0.14% | 99.95% |
| raw_jitter | 0.9988 | 0.30% | 99.98% |
| no_weights | 0.8919 | 0.60% | 69.00% |
| no_slow_windows | 0.8583 | 0.56% | 29.25% |

## Interpretación y pendientes

- Mantener un F1 alto en algunos casos no invalida el experimento. Las familias conocidas pueden ser fáciles de distinguir; las fallas ante familias o dispositivos excluidos deben permanecer visibles.
- Bajar falsas alarmas subiendo el umbral puede omitir ataques. Se reportan ambos errores y el umbral congelado antes del test.
- No hay NaN/inf en el escaneo completo, pero eso no excluye artefactos, redundancia, sesgo de laboratorio o ruido de etiquetas.
- Las cifras anteriores no deben combinarse con el LODO histórico 8/1 ni interpretarse como una mejora causal sobre él.
- El diagnóstico de coincidencias exactas está en cada metrics.json y en summary.csv. No certifica ausencia de casi duplicados ni de dependencia estadística.
- No se crearon intervalos por paquete que supongan independencia falsa. Faltan sesiones/días independientes para incertidumbre operacional.
- No se ejecutó una captura del router ni se certificó el extractor. La evidencia en tu cámara sigue pendiente.
- Los resultados nuevos y antiguos permanecen separados. Los candidatos 6/2/1 (`device_1_rf` a `device_9_rf`) están disponibles en el dashboard mediante el modo de enrutamiento ciego por dispositivo (verificados con `candidate_hashes.json`).

## Artefactos y verificaciones

`protocol_before_test.json`, `environment.json` y `data_manifest.json` registran el protocolo, versión y origen. Cada experimento tiene configuración, modelo, matriz de confusión y predicciones con archivo/fila de procedencia. `summary.csv` y `results.json` agregan las mediciones.

Se ejecutaron 20 pruebas automatizadas del proyecto y del nuevo protocolo. El script de captura pasó análisis sintáctico de PowerShell; no fue ejecutado sobre una interfaz real.

Para capturar el IoT Wi-Fi con un router de compañía, consultar [VALIDACION_REAL.md](../../VALIDACION_REAL.md). El próximo dato necesario es marca/modelo del router; no son necesarias sus contraseñas.
