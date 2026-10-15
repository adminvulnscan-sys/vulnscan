> Revision actual: `panel-429-v6`. La correccion con 429 informes se describe
> al final; las secciones anteriores conservan la evidencia historica.

# Medición de carga del panel

Revisión `panel-trace-v4`. Las pestañas siguen precargadas con
`on_change="ignore"`; navegar no provoca una nueva ejecución. No se cambia
Supabase, facturación, reservas ni autorización PDF.

## Contraste con 4245f5a

El cambio 48b663e modificó el recorrido al ejecutar/persistir escaneos y añadió
la reserva. Ese recorrido no se ejecuta al entrar o navegar sin iniciar uno.
La consulta de todo el historial, los permisos PDF por documento y el feed
síncrono ya existían en 4245f5a. Las correcciones posteriores normalizan informes
estructurados que antes podían interrumpir el recorrido antes de Configuración.
Esto no demuestra qué operación demora la cuenta publicada.

## Instrumentación

Desde la entrada privada hasta terminar Configuración se registran importaciones,
perfil, restauración del último escaneo, sincronización inicial, barra lateral,
cabecera y seis secciones. Se separan ejecuciones de consultas/RPC de la interfaz,
normalización, generación PDF y petición/decodificación del feed. Las llamadas
internas del monitor se incluyen en su tiempo de bloque, sin modificarlo.

`operation=panel_profile_timing` muestra fase, cantidad de llamadas, milisegundos
acumulados/máximos y posiciones inicial/final en el recorrido. `TOTAL` incluye
el número agregado de informes y cuántos tienen JSON estructurado. Los tiempos
de bloque incluyen sus consultas hijas: **no deben sumarse todos entre sí**.
`run` es aleatorio por ejecución, no un identificador de usuario.

No se registran consultas, parámetros, resultados, correos, UUID de cuenta,
dominios, informes, claves ni mensajes de excepciones. No se memorizan permisos.

## Evidencia y siguiente dato necesario

127 pruebas Python aprobadas. Reproducción con servicios de lectura simulados,
25 y 50 informes estructurados distintos, 150 hallazgos por informe, 100 ms por
autorización y un segundo de espera de feed. Reportes bloquea aproximadamente
3,4 y 6,3 segundos antes de Amenazas; Configuración tarda milisegundos al llegar.
Es latencia controlada, **no una medida de producción**. No se conoce todavía
el volumen real de la cuenta administradora; no se afirma que estas muestras
lo igualen. Tampoco se ha identificado todavía el bloqueo real publicado.

Tras publicar, entrar al panel y recargar una vez sin iniciar operaciones.
En los registros de Streamlit, filtrar `operation=panel_profile_timing` y aportar
una captura de un bloque del mismo `run`, hasta `phase=TOTAL`. Esa única captura
permite conocer volumen y atribuir la demora sin compartir datos personales.
La reparación concreta queda pendiente de esa evidencia; esta entrega es
diagnóstico, no una declaración de resolución.


## Correccion posterior: panel-parallel-v5

Se conserva el recorrido completo y la precarga de todas las pesta?as. Las
lecturas RPC de autorizacion PDF se deduplican por ID dentro de un solo render
privado y se ejecutan con un maximo de cuatro conexiones concurrentes. Cada
informe sigue consultando la misma funcion del servidor, con p_consume=false;
no se persisten permisos en session_state, disco ni cache compartida. Nuevos
renders vuelven a comprobar derechos. El consumo explicito sigue siendo una
operacion separada del servidor y descarta su lectura previa. Las lecturas
anticipadas no sobrescriben saldos despues de consumir un credito.

El feed publico comienza en paralelo con la preparacion ya existente y se
recoge antes de terminar Amenazas; no se aplaza ninguna pesta?a ni se a?ade
una espera. Cache publico de una hora como antes, sin contexto privado. Su
peticion conserva timeout y endpoint; la espera restante se registra como
threat_feed_wait. No se ejecutan motores ni llamadas Stripe para la precarga.

Comparacion local controlada de todo el recorrido, mismos informes estructurados
(150 hallazgos cada uno), RPC de 100ms y feed de 1s, procesos nuevos/cache frio:
25 informes: 5570 -> 1887 ms; 50 informes: 8425 -> 2234 ms. Son simulaciones de
latencia; no se afirma que ese sea el volumen ni la latencia de la cuenta real.
133 pruebas de la suite aprobadas y prueba adicional con SDK PostgREST real y
transporte HTTP simulado: clientes aislados, RPC solo lectura. Chrome local:
10 cambios de pesta?a, contador de ejecuciones constante, contenido precargado.

Causa comprobada local: espera serial y consultas duplicadas por el mismo PDF,
mas feed sincrono despues de Reportes. El parche reduce el camino critico
solapando trabajo, sin saltarse autorizaciones o mover carga al primer clic.
La rapidez de la cuenta publicada sigue pendiente de confirmacion. No se
restaura codigo antiguo ni se cambian esquema, reservas, webhook o facturacion.


## Correccion con el volumen confirmado: panel-429-v6

Git 4245f5a ya utilizaba pesta?as precargadas; se mantiene ese recorrido, sin
restaurar el proyecto antiguo. La preparacion completa del archivo historico
se elimina del inicio para Pro/Enterprise, incluida la cuenta interna admin.
La lista conserva todos sus registros, estilos, filtros y botones; consulta
solo metadatos (y created_at cuando consta en el ultimo informe recuperado).
No descarga los resultados JSON de 429 informes ni genera sus archivos PDF.

Se usa la descarga diferida nativa disponible en Streamlit 1.57, comprobada
con el paquete instalado y en Chrome. Cada clic verifica nuevamente la
identidad autenticada y billing_authorize_pdf(p_consume=false). Solo entonces
lee el informe completo, limitado por ID y propietario, valida ambos campos
y genera el PDF con los mismos normalizadores y formato. No consume creditos
ni almacena permisos. Dos descargas vuelven a comprobar el servidor. Las
rutas Basic de compra/desbloqueo y sus consumos explicitos no se sustituyen.
Esto difiere la preparacion de un archivo solicitado, NO carga pesta?as al
abrirlas ni mueve el trabajo del archivo historico a otro punto del inicio.

En Chrome se reprodujo ademas que la inicializacion de componentes de compra
podia provocar ejecuciones completas adicionales. stripe_action conserva su
controlador de Checkout sin cambios (AST comparada contra HEAD anterior),
pero su renderizado utiliza un fragmento. Las actualizaciones de preparacion
se limitan al control; una compra explicita conserva su rerun y todas sus
validaciones, idempotencia y navegacion. No se modifica JavaScript de Stripe,
webhook, esquema, reservas, saldos ni planes.

Comparacion local completa con 429 informes ficticios estructurados, 150
hallazgos cada uno, RPC simulada100ms y feed1s, cache frio: 12187 -> 2013ms
hasta Configuracion (AppTest total externo 12475 -> 2230ms). PDFs preparados
al iniciar: 430 -> 1 (Dashboard); lecturas PDF: 429 -> 1. No son mediciones de
la cuenta publicada ni datos reales del usuario, aunque igualan su volumen.
Chrome con los 429 informes: diez cambios de pesta?a, contador del servidor
constante, 13-178ms incluyendo CDP/frames; descarga efectiva de PDF valido
(4341bytes ficticios), sin nueva ejecucion del panel. Las verificaciones
iniciales del marcador HTML se corrigieron para no confundir virtualizacion
fuera de pantalla ni sesiones previas con ejecuciones de esta prueba.

Suite final: 140 pruebas aprobadas, incluido rechazo de fila/propietario
incorrecto; ejecucion completa final registrada localmente.
Pendiente: confirmar mejora autenticada publicada con revision panel-429-v6.
No se han realizado pagos, motores ni escrituras remotas.
