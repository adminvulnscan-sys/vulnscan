# Proyecto de trabajo único: original

Desde esta intervención el proyecto de trabajo es
`C:\Users\ruizm\OneDrive\Escritorio\saas_seguridad`.
La copia `C:\Users\ruizm\VulnScan-workspaces\VulnScan-panel-anterior-20261007-154754`
se conserva íntegra como respaldo y no se elimina.

## Respaldo anterior a la incorporación

`C:\Users\ruizm\VulnScan-backups\Original-antes-consolidacion-20261007-215124\original-completo.zip`

El ZIP contiene código, recursos, cambios sin commit, archivos locales sensibles
y Git. Se verificó su integridad y se guardaron hashes y estado Git en archivos
locales del mismo respaldo. Se excluyeron respaldos anteriores, cachés y entornos
generados, que permanecen en su ubicación original. No se sobrescribió ningún
respaldo anterior. Los secretos nunca se mostraron ni se incorporaron al commit.

## Incorporado

- app.py y vulnscan.py recuperan las pestañas, barra lateral, formulario y
  distribución anteriores, con la fila de créditos reales y el logo limpio.
- El selector único usa panel_language_picker.py y panel_language/index.html,
  con banderas, opciones Español/English y protocolo nativo de componentes.
- Checkout y portal se generan solo mediante acciones explícitas. Los mensajes
  de error no muestran payloads y el registro filtra el diagnóstico técnico.
- Landing terminada, traducciones, motores/planes descritos y recursos coinciden
  entre ambas copias: ya estaban incorporados, no se reescribieron.
- supabase/tests/billing_schema_metadata.sql es solo lectura; no se ejecutó.
- tests/test_panel_controls.py y tests/preview_private_panel.py permiten revisar
  la interfaz original sin cargar .env, ejecutar motores ni usar cuentas remotas.

La comparación confirmó que no había ediciones independientes posteriores en
los dos scripts a sustituir. Los auxiliares exclusivos del rediseño descartado
(private_ui.py, su nota y scripts/pruebas específicos) se retiraron del proyecto
activo solo después de comprobar que no habían recibido cambios posteriores.
Sus versiones completas están en el ZIP. No se copiaron configuraciones ni Git
desde la copia restaurada.

## Configuración y comprobaciones

.env y secrets.toml existentes conservan exactamente sus bytes anteriores.
La configuración efectiva inspeccionada apunta a Supabase original
qlvnxbthwwcujhimdsmw y Stripe test, sin sobrescrituras de proceso observadas.
No se cambió silenciosamente de entorno. Las pruebas omitieron esos servicios.

Pasaron cuatro pruebas del panel y cuatro de plantilla de landing, sintaxis
Python y git diff --check. Chrome sobre las vistas aisladas confirmó:
- Panel: seis pestañas, ES → EN → ES, conservación del índice guardado, teclado
  Enter/Escape, ausencia de selector duplicado y selector visible en móvil.
- Landing: ES → EN → ES, cifras 0/4/72, ausencia de marcadores sin resolver,
  navegación a Cómo funciona/Producto/Planes/FAQ con título visible y destino del
  botón de ejemplo de resultados.

El controlador Checkout se usa con Stripe/Supabase simulados: renderizar no crea
sesiones, pulsar compra produce una sola llamada simulada y 42703 se maneja sin
filtrar datos de la excepción. Las diez rutas conservan precios/tipos/modalidades.
No se crearon compras reales, se ejecutaron escaneos, se aplicaron migraciones,
se escribieron datos remotos ni se hicieron push/despliegues.

Pendiente: revisión del esquema y RLS del Supabase ORIGINAL, autenticación real,
pagos y concurrencia completos. Incorporar el código no resuelve la columna
usuarios.stripe_customer_id. No se reaplicaron 001/002 ni se desbloqueó la API.

## Abrir y ejecutar

En PowerShell:

```powershell
Set-Location 'C:\Users\ruizm\OneDrive\Escritorio\saas_seguridad'
code .
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8530 --browser.gatherUsageStats false
```

Abrir explícitamente http://127.0.0.1:8530, no una pestaña de 8520/8521. Si 8530
está ocupado, detener únicamente el servidor que se reconozca como propio.
Se conservó APP_URL tal como estaba: el puerto elegido evita confundir servidores;
los retornos de pago locales deberán revisarse al preparar las pruebas de pago.

Para revisar sin servicios: ejecutar tests/preview_private_panel.py en otro
puerto. Los servidores de comprobación de esta intervención se detuvieron al
terminar. Reiniciar instancias anteriores para cargar el código consolidado.

Para deshacer, preservar primero cambios posteriores, recuperar los archivos
correspondientes del ZIP y retirar únicamente los nuevos que registra su manifest.
No restaurar Git ni credenciales indiscriminadamente sobre trabajo posterior.
Este respaldo local no es una copia de los datos de Supabase o Stripe.
