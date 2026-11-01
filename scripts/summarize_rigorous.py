"""Create a readable report from completed, immutable experiment records."""
from pathlib import Path
import hashlib
import json
import statistics
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

root=Path(__file__).resolve().parents[1]
run=root/'experiments/rigorous_v1'
status=json.loads((run/'status.json').read_text(encoding='utf-8'))
assert status['completed']
results=json.loads((run/'results.json').read_text(encoding='utf-8'))
manifest=json.loads((run/'data_manifest.json').read_text(encoding='utf-8'))
lines=['# Resultados del protocolo exigente — 1 de noviembre de 2026','',
       '**Estado: benchmark de desarrollo; no autorizado para producción.**','',
       f"Se completaron {len(results)} experimentos con datos reales de laboratorio. "
       f"Se inspeccionaron {sum(m['rows'] for m in manifest):,} filas en {len(manifest)} archivos; "
       f"{sum(m['nonfinite_rows_full_file'] for m in manifest):,} filas con valores no finitos.", '',
       'Se conservaron bloques en seis posiciones por captura. El test tardío usa hasta '
       '1.000 benignos y 200 ataques por bloque y archivo. La distribución de clases es '
       'la de esta selección, no la prevalencia de una red doméstica.', '',
       '## Dispositivo externo: seis para ajustar, dos para calibrar y uno para probar','',
       'Promedios no ponderados sobre nueve dispositivos. El umbral ajustado busca FPR '
       'empírico ≤ 0,1 % en la calibración; el objetivo no garantiza esa tasa fuera de muestra. '
       'Se muestra el umbral fijo para distinguir dificultad de datos y efecto del umbral.', '',
       '| Modelo | Regla | F1 medio | FPR medio | Peor FPR | Menor recall |',
       '|---|---|---:|---:|---:|---:|']
for model in ['lr','rf','gb']:
    group=[r for r in results if r['name'].startswith('device_') and r['model']==model]
    assert len(group)==9
    for rule in ['test_fixed_0_5','test_calibrated']:
        m=[r[rule] for r in group]
        lines.append(f"| {model} | {'0,5' if rule.endswith('0_5') else 'Ajustado'} | "
                     f"{statistics.mean(x['f1'] for x in m):.4f} | "
                     f"{statistics.mean(x['fpr'] for x in m):.2%} | "
                     f"{max(x['fpr'] for x in m):.2%} | {min(x['recall'] for x in m):.2%} |")
lines+=['','## Familia y dispositivo nunca vistos — Random Forest','',
        '| Familia excluida | Dispositivo | F1 fijo 0,5 | F1 ajustado | Recall ajustado | FP | FN |',
        '|---|---:|---:|---:|---:|---:|---:|']
for r in results:
    if r['name'].startswith('unknown_'):
        m=r['test_calibrated']
        lines.append(f"| {r['name'].split('_')[1]} | {r['test_devices'][0]} | "
                     f"{r['test_fixed_0_5']['f1']:.4f} | {m['f1']:.4f} | {m['recall']:.2%} | {m['fp']} | {m['fn']} |")
lines+=['','## Ablaciones predefinidas — Random Forest','',
        'Resultados exploratorios. No se seleccionó un ganador para producción mirando estos tests.', '',
        '| Representación | F1 externo medio ajustado | FPR externo medio | Menor recall |',
        '|---|---:|---:|---:|']
for variant in ['sanitized','raw_jitter','no_weights','no_slow_windows']:
    group=[r for r in results if r['variant']==variant and r['model']=='rf' and
           (r['name'].startswith('device_') if variant=='sanitized' else r['name'].startswith('ablation_'))]
    assert len(group)==9
    m=[r['test_calibrated'] for r in group]
    lines.append(f"| {variant} | {statistics.mean(x['f1'] for x in m):.4f} | "
                 f"{statistics.mean(x['fpr'] for x in m):.2%} | {min(x['recall'] for x in m):.2%} |")
lines+=['','## Interpretación y pendientes','',
        '- Mantener un F1 alto en algunos casos no invalida el experimento. Las familias conocidas '
        'pueden ser fáciles de distinguir; las fallas ante familias o dispositivos excluidos deben permanecer visibles.',
        '- Bajar falsas alarmas subiendo el umbral puede omitir ataques. Se reportan ambos errores y el umbral congelado antes del test.',
        '- No hay NaN/inf en el escaneo completo, pero eso no excluye artefactos, redundancia, sesgo de laboratorio o ruido de etiquetas.',
        '- Las cifras anteriores no deben combinarse con el LODO histórico 8/1 ni interpretarse como una mejora causal sobre él.',
        '- El diagnóstico de coincidencias exactas está en cada metrics.json y en summary.csv. '
        'No certifica ausencia de casi duplicados ni de dependencia estadística.',
        '- No se crearon intervalos por paquete que supongan independencia falsa. Faltan sesiones/días independientes para incertidumbre operacional.',
        '- No se ejecutó una captura del router ni se certificó el extractor. La evidencia en tu cámara sigue pendiente.',
        '- Los resultados nuevos y antiguos permanecen separados. Ningún candidato fue promovido al registro del dashboard.', '',
        '## Artefactos y verificaciones','',
        '`protocol_before_test.json`, `environment.json` y `data_manifest.json` registran '
        'el protocolo, versión y origen. Cada experimento tiene configuración, modelo, '
        'matriz de confusión y predicciones con archivo/fila de procedencia. `summary.csv` '
        'y `results.json` agregan las mediciones.', '',
        'Se ejecutaron 20 pruebas automatizadas del proyecto y del nuevo protocolo. '
        'El script de captura pasó análisis sintáctico de PowerShell; no fue ejecutado sobre una interfaz real.', '',
        'Para capturar el IoT Wi-Fi con un router de compañía, consultar [VALIDACION_REAL.md](../../VALIDACION_REAL.md). '
        'El próximo dato necesario es marca/modelo del router; no son necesarias sus contraseñas.']
(run/'RESULTADOS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
hashes={str(p.relative_to(run)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in run.glob('*/candidate.joblib')}
(run/'candidate_hashes.json').write_text(json.dumps(hashes,indent=2),encoding='utf-8')
print('\n'.join(lines[:22]))
