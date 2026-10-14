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
