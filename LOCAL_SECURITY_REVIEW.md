# Facturaci?n y sesiones: fases 1 y 2

## Estado actualizado: flujo de creditos, 05/10/2026

El usuario confirma migraciones 001/002, billing_ownership.sql y rechazo de
cambios directos de plan y los tres creditos en VulnScan-Pruebas: valores
intactos y fixtures revertidos. Estas pruebas remotas no se repiten.

Respaldo previo: .local-backups/credit-flow-20261005-191201/; manifest registra
originales y archivos nuevos. Se conservan las modificaciones anteriores.

PDF: consultar autorizacion al renderizar no consume; la compra suelta requiere
pulsar Desbloquear. Los informes ya autorizados y las suscripciones validas
mantienen acceso sin otro consumo. Escaneo: comprobar/marcar en curso precede
al descuento; finally libera el estado ante excepciones. El reintento conserva
la operacion del mismo objetivo incluso tras perder la respuesta de Supabase.
El bloqueo es por sesion; no se afirma exclusion entre sesiones distintas.

29 pruebas Python locales con servicios simulados aprobadas, incluidas nueve
nuevas. Sintaxis y git diff --check correctos; ambas interfaces equivalentes.
No se ejecutaron motores ni llamadas remotas. billing_delivery.sql preparado,
pendiente de ejecutar: duplicados de evento/Checkout, compras distintas en
distinto orden, lease ocupado/sustituido y rollback de un fallo tras incrementar
creditos. Todos los fixtures de ese archivo se revierten.

Pendientes: concurrencia PostgreSQL con conexiones independientes, ciclo HTTP
y Stripe test completo, doble Checkout concurrente y reserva/reembolso duradero
ante fallos del motor. Reintentar sin doble consumo no equivale a reembolsar.
No se han realizado cobros, despliegues, push ni cambios en produccion.

## Respaldo y alcance

Se conservaron los cambios actuales y los archivos Microsoft/. La fase 1 tiene
su respaldo en `.local-backups/20261004-224216/`. Antes de la fase 2 se respaldaron
app.py, vulnscan.py, billing.py, esta nota, el webhook, config.toml y las pruebas
anteriores en `.local-backups/phase2-20261004-224827/`. Ambos manifiestos registran
hashes de originales y archivos nuevos. En la fase 2 billing.py s? exist?a y est?
respaldado. No se leyeron secretos ni se hicieron commits o push.

Para deshacer solo la fase 2, restaure los archivos de su manifiesto `existing`
y revise/elimine individualmente los de `new` si no tienen cambios posteriores.
Esto conserva las correcciones de la fase 1. No elimine directorios completos.
Los respaldos est?n excluidos de Git y sus hashes se han comprobado.

## Implementado localmente

El webhook verifica HMAC-SHA256 mediante Web Crypto sobre el cuerpo original,
acepta varias firmas v1 para rotaci?n y exige una diferencia m?xima de 300
segundos respecto del timestamp firmado, tambi?n hacia el futuro. Rechaza JSON
inv?lido, m?todos distintos de POST, configuraci?n ausente y mezcla de eventos
live/test. La edad del evento no se confunde con la edad de la firma: Stripe puede
reenviar un evento antiguo con una firma nueva.

Se consulta Checkout y la suscripci?n actuales mediante peticiones de lectura a
Stripe. Solo una sesi?n completa y pagada concede cr?ditos. Se validan usuario
UUID, cliente, modalidad, precio permitido, cantidad uno y, en compras sueltas,
importe positivo y moneda exactos. No se conceden compras de importe cero ni se
admiten descuentos/impuestos que cambien el importe de una compra suelta sin
adaptar expl?citamente esta validaci?n. No se usa customer_email para titularidad.

La identidad llega de user_id en los metadatos que la app establece despu?s de
validar la sesi?n Supabase. El webhook exige ese UUID tambi?n en la suscripci?n.
La base comprueba que existe en auth.users. El correo de ese usuario autenticado
solo localiza su perfil antiguo mientras se establece billing_user_id: no se usa
el correo recibido de Stripe ni se reconcilian suscripciones por coincidencia de
correo. Perfiles ambiguos o identidades contradictorias se rechazan.

La migraci?n 002 a?ade un ledger de eventos, compras y gastos. billing_apply
registra el evento y concede el cr?dito en una misma transacci?n. event_id es
?nico y checkout_id tiene una segunda barrera: dos eventos distintos de la misma
compra tampoco conceden dos cr?ditos. Los saldos se incrementan en SQL, sin
leerlos y volver a escribirlos desde el webhook.

Una concesi?n temporal por cuenta (120 segundos) serializa el procesamiento.
Stripe se consulta nuevamente despu?s de obtenerla. Los trabajadores con una
concesi?n vencida o sustituida no pueden confirmar cambios ni liberar la de otro
trabajador. Cuenta ocupada o error de Stripe/BD devuelve 500 para reintento; no se
marca el evento como completado. Una sesi?n todav?a impagada no se marca aplicada,
permitiendo su confirmaci?n as?ncrona posterior.

Para eventos de renovaci?n, impago, cambio, pausa, reactivaci?n o cancelaci?n se
aplica el estado actual de la suscripci?n, no la instant?nea del evento antiguo.
Una suscripci?n antigua no sustituye otra m?s reciente: se compara su fecha de
creaci?n. Si hay empate entre IDs diferentes se mantiene el v?nculo y requiere
revisi?n. Solo status active, ?ltima factura pagada y periodo vigente conservan
Pro/Enterprise. Cancelar al final del periodo mantiene acceso durante el periodo
pagado; canceled, impago o periodo vencido dejan Basic. La pol?tica es suspensi?n
inmediata ante impago, sin periodo de gracia. No se implementan trials de Stripe.

La app y el webhook comparten el cat?logo en
`supabase/functions/_shared/billing_catalog.json`. Los IDs existentes son valores
por defecto, no secretos. Para pruebas, hay que sustituirlos con variables
STRIPE_PRICE_PRO_RECURRENTE, STRIPE_PRICE_ENTERPRISE_RECURRENTE,
STRIPE_PRICE_PRO_UNICO, STRIPE_PRICE_ENTERPRISE_UNICO y STRIPE_PRICE_PDF_UNICO en
AMBOS procesos. El webhook usa STRIPE_LIVEMODE=false por defecto y lecturas Stripe
con API 2025-03-31.basil. Se admiten subscription y parent.subscription_details de
las facturas; los periodos pueden venir de la suscripci?n o de su ?nico item.

La app reutiliza el cliente Stripe vinculado. Para una suscripci?n existente,
los cambios de plan se dirigen al portal de Stripe; solo una cancelada o expirada
permite contratar otra. Gestionar tarjetas usa una sesi?n de portal del cliente.
El portal debe configurarse en Stripe de prueba para los planes autorizados.
Cancelar/reactivar sigue comprobando identidad y exige confirmaci?n Stripe.
El retorno de pago no concede derechos. El perfil se refresca en cada rerun y
no mantiene planes de pago cuando su periodo confirmado ha vencido.

Los consumos de escaneos pasan por billing_spend, que ?nicamente descuenta,
usa auth.uid(), bloquea el perfil e impide saldo negativo. La autorizaci?n de PDF
comprueba en el servidor que el escaneo persistido pertenece al usuario antes de
servir bytes. Su consumo es idempotente por informe y el derecho queda guardado
para futuras descargas. Se retir? el desbloqueo prematuro del upsell. Los informes
sin ID persistido no se pueden autorizar. No se implement? a?n reserva/reembolso
ante fallo del motor: un cr?dito de escaneo se descuenta al iniciar.

La antigua prueba gratuita elevaba el plan mediante escrituras del cliente. Se
ha retirado esa concesi?n; la pantalla informa que necesita configuraci?n segura
y ofrece directamente la contrataci?n mediante Checkout.
Las pruebas gratuitas antiguas y planes manuales necesitan revisi?n antes de
migrar; no se presentan como suscripciones Stripe comprobadas.

## Migraciones y RLS preparadas, sin ejecutar

Aplicar primero 202610040001_billing_links.sql y luego
202610040002_atomic_billing.sql SOLO sobre una instancia local desechable o un
proyecto de pruebas con una copia del esquema real. La segunda necesita los
campos existentes de usuarios (incluidos contadores, fecha_vencimiento como texto,
cancelacion_pendiente y reporte_pdf_desbloqueado como texto), auth.users y
escaneos(id,email_cliente). No crea el esquema original que falta en el repo.
Hay que revisar tipos, defaults, unicidad de email, triggers y duplicados antes
de aplicar. Las funciones SECURITY DEFINER deben pertenecer al administrador de
migraciones; search_path est? fijado y su permiso EXECUTE est? restringido.

Las tablas de facturaci?n tienen RLS y no conceden permisos a anon/authenticated.
Solo service_role ejecuta claim/apply/release. authenticated puede gastar y
solicitar PDF mediante RPC vinculado a auth.uid(). En usuarios se prepara una
barrera RLS restrictiva por propietario, adem?s de permisos m?nimos para la app;
un trigger impide cambiar plan, cr?ditos, cliente/suscripci?n Stripe, propietario,
fecha, cancelaci?n, trial y desbloqueo de PDF desde el cliente. El perfil inicial
solo permite Basic sin cr?ditos ni v?nculos; su propietario se asigna desde JWT.
Tambi?n se revocan permisos an?nimos y de borrado del perfil.

La interfaz rechaza claves Supabase secret/service_role. Debe usar una clave
p?blica; service_role queda solo en la funci?n Edge. Desactivar verify_jwt para
stripe-webhook en config.toml es necesario para Stripe, que no env?a un JWT
Supabase; la firma del cuerpo es obligatoria y autentica la petici?n.

NO se ha obtenido el esquema ni las pol?ticas reales. Estas protecciones son
c?digo preparado, no una constataci?n de la configuraci?n de producci?n. RLS no
sustituye los permisos por columnas/trigger. Hay que revisar tambi?n herencia de
roles, funciones ya expuestas, propietario de funciones y pol?ticas de escaneos.

## Reconciliaci?n offline

`scripts/reconcile_billing.py` funciona siempre en simulaci?n: no carga .env,
no tiene clientes de red ni modo de aplicaci?n. Recibe una exportaci?n de prueba
con auth_users (id), subscriptions (id,customer,livemode,metadata) y opcionalmente
profiles (billing_user_id,stripe_customer_id,stripe_subscription_id).

Ejemplo, con archivos de prueba conservados fuera del seguimiento de Git:

```powershell
python scripts/reconcile_billing.py .local-backups/test-snapshot.json --dry-run
python scripts/reconcile_billing.py .local-backups/test-snapshot.json --dry-run --reviewed-bindings .local-backups/test-bindings.json
```

Solo propone un v?nculo si hay un UUID conocido en los metadatos o un v?nculo
manual revisado con subscription_id, customer_id, user_id, approved_by,
evidence_ref y evidence_type (authenticated_account_ownership o
verified_paid_checkout). El correo no se acepta como prueba. Los archivos
exportados y las revisiones manuales necesitan procedencia verificada; el modo
offline no certifica su autenticidad. Datos live, m?ltiples suscripciones,
clientes compartidos y v?nculos contradictorios se bloquean para revisi?n.

Las propuestas no conceden cr?ditos hist?ricos ni modifican Stripe. Para aplicar
una propuesta en pruebas, verificar primero la evidencia y la exportaci?n actual,
a?adir user_id a los metadatos de la suscripci?n desde una cuenta administrativa
y sincronizar el estado mediante el flujo de facturaci?n, con lectura fresca de
Stripe y RPC at?mico. No importar ciegamente planes de una exportaci?n antigua.
No se ha ejecutado ninguna reconciliaci?n contra servicios reales.

## Probado con simulaciones

- `python -m unittest discover -s tests -v`: 19 pruebas aprobadas. Aislamiento,
  cierre de sesi?n, retorno manipulado/sin confirmar, cancelaci?n fallida,
  reactivaci?n, cat?logo y portal, claves p?blicas, gasto RPC, bloqueo del PDF
  si falla autorizaci?n y reconciliaci?n sin v?nculo por correo.
- `node --test tests/webhook.test.mjs`: 15 pruebas aprobadas. Firma/rotaci?n,
  antig?edad y manipulaci?n; productos sueltos y Enterprise; duplicados del evento
  y de Checkout; 12 entregas simult?neas con reintentos; compras impagadas,
  renovaci?n, impago, recuperaci?n y cancelaci?n; eventos antiguos e igualdad de
  timestamps; concesi?n sustituida y fallo antes del commit.
- Sintaxis Python comprobada con AST; sintaxis JS/TS mediante node --check;
  git diff --check limpio y hashes de los respaldos verificados.

Las simulaciones de BD comprueban el contrato del webhook, NO los bloqueos reales,
transacciones ni RLS de PostgreSQL. Las pruebas de interfaz extraen funciones con
AST sin iniciar Streamlit, cargar .env ni ejecutar motores. Las peticiones Stripe
se sustituyen por mocks; la red est? prohibida en las pruebas JS.

## Validaci?n pendiente en un entorno de prueba real

No hay PostgreSQL/psql ni Deno disponibles aqu?. No se han aplicado migraciones
ni ejecutado la funci?n Edge real. Node --check no valida imports ni tipos Deno.
Se prepar? supabase/tests/billing.sql con pgTAP, fixtures y rollback para validar
permisos, RLS, duplicados y gastos sobre una instancia desechable. Necesita adaptar
fixtures si el esquema/triggers reales tienen otros campos obligatorios. No se
ha ejecutado y no debe ejecutarse contra producci?n.

En una copia del esquema: aplicar ambas migraciones con administrador, ejecutar
pgTAP y repetir con conexiones simult?neas reales, concesiones caducadas y fallos
antes/despu?s de commit. Despu?s levantar la funci?n local con secretos TEST,
validar imports/tipos con Deno y probar Checkout/portal y los eventos reales de
Stripe test, incluidas firmas y forma exacta de los objetos de su versi?n API.
No se han realizado esos pagos de prueba en este trabajo.

Revisar antes del lanzamiento: cat?logo de precios test/live, portal y cambios
prorrateados, impuestos/descuentos, reintentos de webhook con monitorizaci?n,
reembolsos/disputas, y prevenci?n at?mica de dos Checkout simult?neos antes del
primer v?nculo (todav?a pendiente). No borrar el ledger para volver a procesar
pagos. Para escaneos faltan reserva/reembolso de cr?ditos, SSRF, verificaci?n
persistida de dominio, scheduler separado de la UI, backend API y clasificaci?n
de hallazgos. Estas cuestiones de la revisi?n inicial siguen pendientes.

Referencias consultadas: [webhooks de Stripe](https://docs.stripe.com/webhooks),
[eventos de suscripciones](https://docs.stripe.com/billing/subscriptions/webhooks),
[RLS de Supabase](https://supabase.com/docs/guides/database/postgres/row-level-security)
y [permisos por columna](https://supabase.com/docs/guides/database/postgres/column-level-security).

No se hicieron cobros, escaneos externos, despliegues, push ni cambios en producci?n.


## Correcci?n de perfiles iniciales y propiedad (5 de octubre de 2026)

Antes de aplicar la migraci?n 002 se respaldaron los archivos afectados en
`.local-backups/ownership-20261005-185534/`. El manifiesto permite restaurar la
migraci?n, billing.py, pruebas y esta nota, y registra billing_ownership.sql como
archivo nuevo. Se conservaron los dem?s cambios pendientes.

billing_protect_profile rechaza fecha_vencimiento/fecha_inicio_trial no nulas,
trial_pro_usada=true y cancelacion_pendiente=true al crear un perfil desde el
cliente. Si los booleanos llegan como NULL, se normalizan a false. El alta m?nima
de la app sigue siendo v?lida: Basic, cero cr?ditos, fechas nulas y flags false.

Se retir? lower(email) de los filtros de propiedad, del enlace de pagos, de los
consumos y de las pol?ticas RLS. El fallback para perfiles todav?a sin UUID exige
igualdad exacta con colaci?n C. Una diferencia de may?sculas no identifica a otro
perfil. La autorizaci?n del PDF primero identifica el perfil del UUID y despu?s
compara exactamente su email con email_cliente del informe, incluso con plan Pro.
La validaci?n Python de identidad tambi?n exige el email exacto del usuario Auth.
No se a?aden conversiones globales ni cambios de correos existentes.

Pruebas locales: 20 pruebas Python y 15 JS aprobadas; no hubo llamadas a servicios.
Se a?adi? supabase/tests/billing_ownership.sql (sin dependencia de pgTAP), con
perfiles que difieren solo por may?sculas, altas maliciosas/seguras, lectura y
actualizaci?n RLS, rechazo del PDF ajeno antes/despu?s de vincular UUID, consumos,
compra suelta, suscripci?n y recuperaci?n del ?ltimo escaneo. Todos sus fixtures
se revierten mediante ROLLBACK. Esta prueba SQL NO se ha ejecutado por Codex.

El usuario ha compartido metadatos del esquema real: fecha_vencimiento y
reporte_pdf_desbloqueado son text, cr?ditos integer, usuarios tiene PK(email),
y no hay triggers personalizados de fila en las tablas revisadas. Las pol?ticas
y permisos exportados permiten modificar plan/cr?ditos del propio perfil.
Tambi?n ha confirmado la reproducci?n SQL de ese fallo y su reversi?n en
VulnScan-Pruebas, y la aplicaci?n de la migraci?n 001 all?. La migraci?n 002
corregida y sus pruebas siguen pendientes de ejecuci?n en ese proyecto separado.
Estos resultados no equivalen a una prueba del login real, HTTP o Stripe test.
No se han ejecutado modificaciones en producci?n.
