"""Generador y ejecutor del Notebook Exploratorio (Etapa 1) con datos reales de N-BaIoT."""

import os
import nbformat as nbf
from nbclient import NotebookClient

nb = nbf.v4.new_notebook()

text0 = """# Etapa 1: Obtención y Exploración del Dataset N-BaIoT (9 Dispositivos IoT)
En concordancia con la metodología del informe CINF200, este notebook ejecuta:
1. Inventario real de los **89 archivos CSV** de los 9 dispositivos comerciales del dataset **N-BaIoT** (`data_summary.csv` y `device_info.csv`).
2. Análisis de la distribución y severo desbalance entre tráfico **Benigno (Clase 0)** y ataques de las botnets **Mirai** y **BASHLITE/gafgyt (Clase 1)**.
3. Inspección estadística de las **115 características** extraídas por ventanas temporales amortiguadas (`L5, L3, L1, L0.1, L0.01`) y detección del artefacto de marca de tiempo Unix en `HH_jit_*_mean`."""

code1 = """import os
import pandas as pd
import numpy as np

pd.set_option("display.max_columns", 15)
pd.set_option("display.width", 120)

data_dir = os.path.abspath("./data")
devices_df = pd.read_csv(os.path.join(data_dir, "device_info.csv"))
summary_df = pd.read_csv(os.path.join(data_dir, "data_summary.csv"))
summary_df.columns = [c.strip() for c in summary_df.columns]

print("=== DISPOSITIVOS IoT EN N-BaIoT ===")
print(devices_df.to_string(index=False))
print(f"\\nTotal de archivos CSV en el dataset: {len(summary_df)}")
print(f"Total de instancias (filas) en los 9 dispositivos: {summary_df['Data Count'].sum():,}")"""

text2 = """## 1. Análisis de Desbalance de Clases por Dispositivo y Botnet
A continuación cuantificamos el volumen real de tráfico benigno versus tráfico malicioso (BASHLITE y Mirai) por cada uno de los 9 dispositivos comerciales."""

code2 = """summary_df["DeviceID"] = summary_df["File Name"].apply(lambda x: int(x.split(".")[0]))
summary_df["Categoria"] = summary_df["File Name"].apply(
    lambda x: "Benigno" if "benign" in x else ("Mirai" if "mirai" in x else "BASHLITE")
)

pivot_counts = summary_df.pivot_table(
    index="DeviceID", columns="Categoria", values="Data Count", aggfunc="sum", fill_value=0
).merge(devices_df, on="DeviceID")
pivot_counts["Total_Ataque"] = pivot_counts["BASHLITE"] + pivot_counts.get("Mirai", 0)
pivot_counts["Ratio_Ataque_vs_Benigno"] = (pivot_counts["Total_Ataque"] / pivot_counts["Benigno"]).round(2)

cols_order = ["DeviceID", "DeviceName", "Benigno", "BASHLITE", "Mirai", "Total_Ataque", "Ratio_Ataque_vs_Benigno"]
print("=== DISTRIBUCIÓN DE TRÁFICO POR DISPOSITIVO (DESBALANCE REAL) ===")
print(pivot_counts[cols_order].to_string(index=False))"""

text3 = """## 2. Verificación de Calidad de Datos y Artefacto `HH_jit` en Dispositivo 1 (*Danmini Doorbell*)
Cargamos muestras reales de tráfico benigno (`1.benign.csv`) y de ataque (`1.mirai.udp.csv`) para verificar ausencia de valores nulos y observar el comportamiento de las 115 características."""

code3 = """df_benign = pd.read_csv(os.path.join(data_dir, "1.benign.csv"), nrows=5000)
df_mirai = pd.read_csv(os.path.join(data_dir, "1.mirai.udp.csv"), nrows=5000)

print(f"Dimensiones Benigno (muestra): {df_benign.shape} | Nulos totales: {df_benign.isnull().sum().sum()}")
print(f"Dimensiones Mirai UDP (muestra): {df_mirai.shape} | Nulos totales: {df_mirai.isnull().sum().sum()}")

cols_preview = ["MI_dir_L0.01_weight", "H_L0.1_weight", "HH_L0.01_magnitude", "HpHp_L0.1_weight", "HH_jit_L0.1_mean"]
print("\\n=== ESTADÍSTICAS DESCRIPTIVAS: TRÁFICO BENIGNO (Dispositivo 1) ===")
print(df_benign[cols_preview].describe().round(3))

print("\\n=== ESTADÍSTICAS DESCRIPTIVAS: ATAQUE MIRAI UDP (Dispositivo 1) ===")
print(df_mirai[cols_preview].describe().round(3))"""

nb.cells = [
    nbf.v4.new_markdown_cell(text0),
    nbf.v4.new_code_cell(code1),
    nbf.v4.new_markdown_cell(text2),
    nbf.v4.new_code_cell(code2),
    nbf.v4.new_markdown_cell(text3),
    nbf.v4.new_code_cell(code3),
]

nb.metadata["kernelspec"] = {
    "display_name": "Python 3",
    "language": "python",
    "name": "python3",
}

output_dir = os.path.dirname(os.path.abspath(__file__))
output_path = os.path.join(output_dir, "01_exploracion_dataset.ipynb")

client = NotebookClient(nb, timeout=120, kernel_name="python3", resources={"metadata": {"path": output_dir}})
client.execute()

with open(output_path, "w", encoding="utf-8") as f:
    nbf.write(nb, f)

print(f"[OK] Notebook exploratorio generado y ejecutado con salidas reales en: {output_path}")
