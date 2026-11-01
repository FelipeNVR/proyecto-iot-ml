# Validación con datos más exigentes y preparación de captura real

> **Alcance acordado — 1 de noviembre de 2026:** por solicitud del usuario, la
> captura en su router y las pruebas con cámaras físicas quedan pausadas. La
> presentación del 2 de noviembre se centra en entrenamiento y evaluación offline
> con N-BaIoT. El acceso al router y nuevas capturas no son requisitos para esta
> entrega. Las instrucciones de hardware se conservan para una etapa posterior.

## Qué se implementó

El nuevo módulo `src/models/rigorous.py` escanea los 89 CSV completos y verifica
esquema, conteo y valores no finitos. Guarda hashes SHA-256 y posiciones originales.
No sintetiza tráfico, cambia etiquetas ni descarga datos de terceros.

Antes de evaluar, guarda protocolo y versión de código. Extrae bloques contiguos
en posiciones 10/30 % (entrenamiento), 50/65 % (calibración), 80/95 % (test).
Por bloque selecciona hasta 1.000 filas benignas y 200 por archivo de ataque.
La selección cubre fases distintas; no reproduce la prevalencia de una red real.
Los huecos están medidos en filas, no son un embargo temporal certificado sin timestamps.

Compara LR, RF y GB con hiperparámetros fijos. Para cada dispositivo externo usa
otros seis para ajustar y dos para elegir el umbral. No usa al dispositivo externo
para elegir variables, umbral o hiperparámetros. Es un esquema 6/2/1, más restrictivo
que el histórico 8/1; sus medias no son comparaciones de protocolos idénticos.

Pruebas adicionales de RF excluyen una botnet completa del entrenamiento y de la
calibración, evaluándola en un dispositivo no visto. Esto mide transferencia a esa
familia, no demuestra detección de cualquier zero-day. Se omiten los casos sin
ejemplos de esa familia en el dispositivo externo; no se rellenan con cero.

Se comparan tres ablaciones predeterminadas en los nueve dispositivos: jitter
crudo, eliminación de contadores `weight` y eliminación de ventanas lentas.
Son experimentos exploratorios, no selección sobre el test para promover un ganador.

Cada experimento publica ambas reglas: umbral fijo 0,5 y umbral seleccionado con
benignos independientes para un objetivo empírico de FPR ≤ 0,1 %. Ese objetivo es
una configuración de investigación, no una garantía ni un requisito operacional
acordado. Puede elevar mucho los falsos negativos; se publican ambos errores.
Elegir el umbral no calibra automáticamente las probabilidades. Consulte la
[documentación oficial de umbrales](https://scikit-learn.org/stable/modules/classification_threshold.html).

Los registros incluyen precision, recall, F1, FPR, ROC-AUC, average precision,
Brier, matriz de confusión, predicciones y procedencia por fila. Una métrica
indefinida se muestra como ausente. La sensibilidad sin coincidencias exactas
excluye del test vectores presentes en entrenamiento o calibración; cambia la
población y no reemplaza la evaluación principal. No se deduplican automáticamente
capturas que pueden contener repeticiones físicamente legítimas.

## Qué sigue pendiente antes de producción

1. Capturas independientes de tu IoT, en varios días/sesiones y actividades.
2. Certificar el extractor con el mismo PCAP contra una implementación de referencia
   y fijar versión, orden, unidades y estado. El prototipo actual corrige el peso
   de jitter y rechaza columnas desconocidas, pero su covarianza aún es aproximada.
3. Etiquetas con evidencia. Una captura recién hecha no se etiqueta automáticamente
   como benigna; desconocido es una categoría válida durante revisión.
4. Prueba en modo observación: sin bloqueo automático y con revisión de alertas.
5. Evaluación de eventos de ataque autorizados en laboratorio aislado o mediante
   PCAP etiquetados independientes. No infectar cámaras de uso cotidiano ni atacar
   la red doméstica para conseguir ejemplos.
6. Medir falsas alertas por hora/dispositivo, episodios detectados, ataques omitidos
   y tiempo hasta la primera alerta. Estas métricas necesitan timestamps y eventos
   reales; no se deducen de la tasa por paquete del benchmark.
7. Acordar tolerancias y observar intervalos de incertidumbre por sesiones/días,
   incluidos periodos sin errores. Cero errores observados no prueba riesgo cero.

Los nuevos candidatos tienen `production_ready: false`. Los resultados históricos
siguen separados y el dashboard ya no copia métricas del RF al IPS. No existe
promoción automática al registro usado por la demo.

## Tu caso: router de compañía e IoT por Wi-Fi

### Equipo identificado el 1 de noviembre de 2026

Las fotografías permiten identificar un **ZTE ZXHN F6600P**. No se copiaron a este
documento las claves, SSID, números de serie ni direcciones MAC de su etiqueta.
La configuración local de Windows indica una puerta de enlace **192.168.1.1** y
conexión del computador por Ethernet. Eso no confirma por sí solo que todo el
tráfico Wi-Fi esté disponible en esa interfaz. No se encontró `dumpcap.exe` en
la ruta habitual de instalación de Wireshark; no se instaló software.

La [ficha oficial ZTE](https://www.zte.com.cn/global/product_index/smart_home_en/ont/zxhn-f6600p/zxhn-f6600p.html)
identifica el modelo y sus interfaces. La documentación pública revisada no
permite confirmar captura PCAP o mirroring en el firmware concreto del proveedor.
No trasladar instrucciones de los modelos F660 o F670 a este equipo suponiendo
que sus menús son iguales.

Próximo paso: entrar desde el computador en `http://192.168.1.1`, autenticarse
con la cuenta propia del router/proveedor y revisar la versión del firmware,
los dispositivos conectados y los menús de diagnóstico. La clave Wi-Fi no es
necesariamente la contraseña de administración. No se necesitan credenciales
compartidas en el chat. Si el proveedor no entregó acceso, solicitarlo por su
canal de soporte.

Comprobar si existe una opción denominada Packet Capture, captura de paquetes,
PCAP, Port Mirroring o Mirror Configuration. Ping, traceroute y exportación de
logs no sustituyen una captura de paquetes. No activar una opción de mirroring
hasta verificar origen, destino y visibilidad del tráfico de las cámaras.

El acceso HTTP de lectura desde el entorno de herramientas no pudo establecerse
por restricciones de sockets. El panel y sus opciones siguen sin inspeccionarse;
no se inició sesión ni se cambió configuración.

Los dispositivos no necesitan cable. Necesitamos un punto de observación que vea
sus paquetes. El modo promiscuo en un computador del mismo Wi-Fi normalmente no
da visibilidad a todo el tráfico de los otros equipos. El modo monitor requiere
hardware/controladores adecuados y puede entregar tramas cifradas, no los datos
IP que espera el extractor. Fuente: [Wireshark, captura WLAN](https://wiki.wireshark.org/capturesetup/wlan).

Orden de opciones:

1. Identificar marca y modelo en la etiqueta física del router o su pantalla de
   información. Basta el modelo; no compartir claves Wi-Fi ni credenciales.
2. Si el router ofrece exportación PCAP/captura LAN o Wi-Fi, usar esa función.
   Verificar que conserva IP/MAC del IoT y ambas direcciones. Una captura WAN
   después de NAT puede perder la identidad individual del dispositivo.
3. Si no ofrece captura, usar un punto de acceso/router de prueba con captura
   soportada y conectar a él solamente el IoT bajo prueba. El IoT sigue por Wi-Fi.
   También puede usarse un AP con uplink observado por un switch con mirroring,
   según el hardware disponible. No hace falta comprar nada antes de comprobarlo.
4. No instalar firmware ni cambiar la configuración del router del proveedor sin
   confirmar compatibilidad y disponer de un plan de recuperación.

La captura real todavía NO se inició: faltan identificar el router, seleccionar
la interfaz visible y verificar el acceso al tráfico del IoT.

## Captura reproducible cuando exista visibilidad

Preparado `scripts/capture_iot.ps1`, para Windows con Wireshark/Npcap disponible.
No configura el router ni crea tráfico. Primero enumerar interfaces:

```powershell
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
```

Ejemplo de invocación, reemplazando IP e interfaz por los valores comprobados:

```powershell
.\scripts\capture_iot.ps1 -Interface 'NUMERO_O_NOMBRE_REAL' `
  -IoTAddress '192.168.1.123' -SessionId 'camara_dia1_reposo' `
  -CapturePoint 'interfaz LAN del punto de observacion verificado' -Minutes 30
```

El script crea una sesión nueva, PCAPNG segmentados cada cinco minutos sin
sobrescribir segmentos, metadatos UTC, plantilla de eventos y hashes. Los comandos
se basan en [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html).
Conservar localmente las capturas: pueden contener información privada.

Antes de una captura larga, comprobar durante dos minutos que se ve tráfico del
IoT en ambas direcciones al abrir su aplicación. Registrar pérdidas de captura y
reloj. Si no se ven esos paquetes, cambiar el punto de observación; no seguir
recopilando tráfico del computador y atribuírselo a la cámara.

Plan inicial de actividades normales, en sesiones separadas: reposo diurno y
nocturno, visualización de video, cambio de resolución si existe, audio, detección
de movimiento, reinicio normal, actualización legítima disponible, reconexión
Wi-Fi y pérdida/restablecimiento de Internet. Registrar actividad y horario real
en `events.csv`; no asignar horas inventadas. No provocar fallos de actualización.

Las primeras sesiones sirven para desarrollo/calibración. Reservar días completos
posteriores, sin inspeccionarlos para ajustar, para aceptación. Una única sesión
de treinta minutos es una prueba de visibilidad, no suficiente cobertura de uso.

## Fuentes externas para ampliar diversidad

[CICIoT2023 de UNB](https://www.unb.ca/cic/datasets/iotdataset-2023.html) ofrece PCAP
y ataques de varias categorías en un banco físico amplio. Sirve para diversificar
amenazas, pero sigue siendo laboratorio. Sus CSV no tienen automáticamente el
esquema N-BaIoT: no concatenarlos ni rellenar columnas faltantes con ceros. Para
comparar con estos modelos hace falta extraer de los PCAP la misma representación
validada; alternativamente, entrenar otro pipeline con su esquema y evaluarlo aparte.

[UNSW-IoTraffic](https://iotanalytics.unsw.edu.au/unsw-iotraffic.html) permite estudiar
comportamiento de consumo y diversidad de uso. Una fuente de tráfico normal sirve
para estudiar falsas alarmas, pero no certifica detección de ataques.

No se descargaron archivos masivos ni se iniciaron capturas de la red durante la
implementación. El paso físico depende de conocer el equipo y verificar visibilidad.
