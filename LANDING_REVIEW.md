# Presentacion publica de VulnScan

## Planes y motores contrastados con el codigo

Respaldo .local-backups/landing-plan-engines-20261006/ con hashes y manifest;
se incluyen traducciones, HTML, CSS, renderizador, nota y test de plantilla.

Escanear_objetivo_real siempre ejecuta el pasivo; Active suma Pro; OWASP suma
Pro y Enterprise. Reglas de acceso en la interfaz: Basic pasivo, Pro pasivo/activo,
Enterprise los tres niveles; tokens comprados habilitan la modalidad puntual.
Analisis activos requieren verificacion por archivo incluso con compra suelta.
La cuota se comprueba antes de elegir el acceso: comprar un credito no la amplia.

Landing incorpora resumen por plan, desplegable de tres motores y bloques separados
de cuotas, resultados/PDF y compras sueltas. Limites Basic/Pro se extraen del AST
de limite_objetivos_unicos_plan en app.py sin importarlo ni ejecutar codigo de app.
Son 3/25 objetivos DISTINTOS al mes, no cantidades de escaneos. Enterprise devuelve
None (sin limite de objetivos). No se prometen escaneos ilimitados por estos numeros.

Pasivo: resolucion A/AAAA, seis cabeceras, validacion/vencimiento TLS, señales CDN
y DNSBL de spam. Activo: servicios/versiones en puertos seleccionados, rutas y
archivos, tecnologias/subdominios/correos publicos, consultas NVD con version y
pruebas de negociacion TLS 1.0/1.1. Enterprise añade comprobaciones web de SQLi/XSS,
cookies, API/CORS, patrones de fugas, metodos HTTP, rate limiting, cabeceras y
referencias a servicios externos. Se describen como indicios, no confirmaciones.
PUT puede escribir un archivo de prueba; requisito intrusivo explicado.

La seccion profunda SSL conserva el error datetime.datetime: no se anuncian firma
SHA-1 ni inventario completo de cifrados como capacidades fiables. No se corrige
el motor en este trabajo. API/programacion no se anuncian como operativas. Se
mantienen tarifas en la pantalla existente: catalogo compartido tiene price IDs,
no importes; hay importes contradictorios en textos previos de la app. No se
duplican ni corrigen precios en la landing ni se modifica facturacion.

Compras segun billing_catalog.json: pro_unico=un credito Active (pasivo+activo),
enterprise_unico=un credito OWASP (los tres), pdf_unico=credito para un informe
propio guardado, sin ejecutar motores. PDF de suscripcion requiere activo/vigente.

Chrome local: ES/EN, tres motores en desplegable abierto, cuotas 3/25 y sin limite,
sin placeholders ni overflow a 320/390/1440px; captura movil revisada. Pruebas de
plantilla y cuota desde fuente real aprobadas. No hubo scans, compras, cambios
de permisos/backend, consultas de cuentas o despliegues.

## Textos comerciales ES/EN

Respaldo .local-backups/landing-copy-20261006/ de HTML, traducciones, CSS y nota,
con hashes y manifest. No se crean archivos nuevos del producto en esta fase.
Nuevo titular/subtitulo y CTA Empezar al acceso existente; CTA Ver ejemplo de
resultados a #results-example, ID añadido a la demostracion sin cambiar IDs de
navegacion existentes. Bloque breve Que es VulnScan y tres pasos en el proceso
existente. Verificacion descrita como requisito de analisis activo segun el codigo.
Planes explican suscripciones Pro/Enterprise, compras sueltas de escaneos y
creditos PDF segun billing_catalog.json. No se añaden tarifas ni limites nuevos.
ES/EN equivalentes y completos; se mantienen limites y uso autorizado.

Cambios: landing/index.html, translations.json y ajustes tipograficos/responsive
en style.css. Logo, movimiento, componentes, entradas, backend y pagos intactos.
Chrome real local: carga y cambio ES/EN, tres pasos, sin placeholders, datos 0/4/72
intactos; boton de ejemplo desplaza hasta la demostracion. Destino de Empezar
comprobado como /?vista=acceso&lang=es/en; no se ejecuto autenticacion remota.
Sin overflow del viewport ni del titular a 320,390 y1440px en ambos idiomas.
Revisadas capturas de escritorio y movil320. Tres pruebas de plantilla y
git diff --check aprobados. Sin scans, cobros ni despliegues.

## Reparacion de Unresolved landing template

Reproduccion exacta con el renderizador guardado antes del recorte del logo y
la plantilla actual: queda pendiente {{hero_logo}} en ES y EN. Ese modulo antiguo
no tiene la sustitucion del nuevo marcador; el modulo actual en disco si la tiene.
No se encontro un falso positivo CSS/JS en los documentos actuales. Esta reproduce
la incompatibilidad entre modulo importado antiguo y recursos actualizados; no
se ha inspeccionado la memoria del proceso del usuario.

Las dos entradas recargan exclusivamente el modulo local landing antes de llamar
public_entry, para no conservar el renderizador importado anterior entre reruns.
La validacion se conserva en Python y componente y acepta el formato real
{{nombre_identificador}}; informa los nombres pendientes, sin borrar expresiones
ni silenciar errores. Bloques JavaScript anidados legitimos no se rechazan.
No se modifica el logo limpio, navegacion, idiomas, facturacion ni escaneo.

Respaldo .local-backups/landing-template-repair-20261006/ con originales/hashes y
manifest del nuevo tests/test_landing_template.py. Tres pruebas locales aprobadas:
renderizado ES/EN con hero_logo y datos anidados; error explicito al faltar un
marcador; conservacion de bloques JS anidados. Sintaxis y diff --check correctos.

Verificacion adicional real en Chrome headless sobre app.py en 127.0.0.1:8512:
sin variables visibles; 0,4,72/100 y barras 0%,40%,72%; ES->EN->ES sincronizado
con query params; cuatro enlaces llegan a ~24px; pestañas operativas; unico
selector; movil 390px sin overflow horizontal. Sin cuentas ni operaciones externas.

## Correcciones verificadas en Chrome local

Respaldo: .local-backups/landing-fixes-20261006/, manifest con hashes y archivo
nuevo landing/component/component.js. Original logo.png.png sin modificaciones.

Se reprodujo un proceso Streamlit que conservaba el modulo Python anterior
mientras leia plantillas nuevas: tras cambios en landing.py es necesario reiniciar
el servidor para cargar el conjunto coherente. Los archivos actuales no contienen
el radio superior. La causa exacta del antiguo DOM visto por el usuario no se da
por inspeccionada: se comprobo el servidor local, no su navegador anterior.

Se elimina document.write y su reemplazo del documento/listeners. component.js
mantiene el receptor de mensajes, monta el DOM y ejecuta explicitamente el runtime
local. Idioma sincronizado mediante protocolo Streamlit, sin acceder al DOM padre.
Los eventos antiguos se limpian con AbortController. El viewport interno es el
unico scroll de la landing: navegacion usa sus coordenadas, no window.scrollTo.
No se afirma que document.write fuera la unica causa de los sintomas anteriores.

demo.json es la fuente de recuentos y escala. Interpolacion incluye las cadenas
traducidas antes de resolver valores, y rechaza plantillas pendientes. C=0, M=4,
indice calculado=72 y riesgo Moderado. Barras de hallazgos en escala 0..10:
0 y 4/10; indice 72/100. Texto y avisos reutilizan esos valores. No se modifica
el calculo del producto real. Se quitaron los dos marcos cuadrados de la escena.

Chrome headless pudo ejecutarse con autorizacion fuera del aislamiento que
bloqueaba GPU. Se probo contra Streamlit en 127.0.0.1:8512, sin cuentas:
0/4/72, sin variables visibles; barras 0%/40%/72%; un selector y ningun radio;
ES->EN->ES con contenido y query params sincronizados; enlaces process/product/
plans/faq y CTA del hero llegan con titulo a ~24px del viewport; pestañas muestran
los dos pasos reales; Enter abre el selector y Escape lo cierra con eventos de
teclado del navegador. Pestañas probadas tambien con evento ArrowRight.
Se revisaron capturas locales de escritorio y movil. En movil de 390px se detecto
overflow de orbitas, se corrigio y se comprobo scrollWidth=clientWidth=390.
Esto no constituye una auditoria completa de accesibilidad ni de todos los equipos.

Pendiente de marca: el PNG tiene transparencia RGBA real y tambien patron de
cuadros incorporado en el contorno, confirmado visualmente. No existe otra version
en el proyecto. No se ha tapado ni redibujado la marca: hace falta un logo limpio
con transparencia para completar el contorno. Las capturas aun muestran ese
patron original. Backend, pagos y escaneos no se tocaron ni ejecutaron.

## Refinamiento: logo, navegacion y resultados

Estado actual que sustituye las referencias anteriores al selector nativo y a
st.iframe: la landing utiliza un componente Streamlit local declarado desde
landing/component/index.html. Todo el documento publico tiene su propio viewport
con scroll. Las anclas usan destinos locales y desplazamiento explicito dentro
del componente, sin acceso al DOM padre. El cambio de idioma comunica solamente
es/en por el protocolo de componentes; sincroniza query params y _vs_lang y
conserva la preferencia local cuando el navegador permite almacenamiento.

Selector integrado en cabecera: banderas SVG, nombre completo de ambos idiomas,
estado seleccionado, foco, Escape y cierre al pulsar fuera. No hay radio duplicado.
El acceso y los terminos mantienen enlaces reales en una nueva pestaña.

La escena central ahora usa logo.png.png original, sin edicion ni deformacion.
Se midieron sus margenes transparentes: bbox alfa (208,46,469,330) en 676x369;
una ventana CSS encuadra el escudo con su V/rayo manteniendo proporcion.

Producto reproduce el panel central aportado: barras, consola, indice, riesgo,
recuentos y avisos. landing/demo.json contiene SOLO datos ficticios (0 criticas,
4 medias). Se aplica la formula del panel: max(5,min(100,100-15*C-7*M)) = 72.
Las barras C/M usan C/(C+M+5) y M/(C+M+5), no porcentajes de vulnerabilidades.
El indice 72/100 es orientativo, no probabilidad ni garantia de seguridad.
Resumen y Plan de accion son pestañas funcionales, con roles ARIA y navegacion
por flechas/Home/End. El plan reproduce los dos pasos existentes en el panel;
no se inventa una lista de remediacion mas completa. Se incluyen cuatro avisos
ficticios de cabeceras correspondientes a comprobaciones del motor pasivo.

Respaldo: .local-backups/landing-refinement-20261006/ con originales, hashes y
manifest de nuevos archivos (landing/component/index.html y landing/demo.json).
No se modificaron las entradas app.py/vulnscan.py ni el panel real en esta fase.
Comprobados sintaxis Python/JS, recursos, claves ES/EN, IDs/destinos y carga
publica mediante AppTest. Captura Chrome headless fallo por proceso GPU, igual
que Edge anteriormente: navegacion, pestañas, idioma y responsive NO se dan
por probados en navegador. La captura aportada basta; no se necesita otra.
Backend, Stripe test y concurrencia siguen pendientes; no hubo llamadas privadas,
escaneos, pagos, despliegues ni cambios de base de datos.

Implementada dentro de Streamlit, antes de inicializar credenciales, Supabase o
motores. Usuarios autenticados, tokens de sesion existentes y retornos legales
o de pago mantienen el flujo anterior. Ambas entradas siguen equivalentes.

Archivos: landing.py; landing/index.html, style.css, motion.js y translations.json.
app.py y vulnscan.py reciben solamente una llamada a la entrada publica al inicio.
Respaldo: .local-backups/landing-20261006/ con originales, hashes y manifest de
archivos nuevos. Para revertir, revisar cambios posteriores, restaurar esas dos
entradas y eliminar solo los nuevos archivos registrados que no se hayan editado.

Se conserva logo.png.png: RGBA, 676 x 369, transparencia real. No se edita ni
deforma. Escena propia SVG/CSS 3D con perspectiva y respuesta limitada al cursor;
sin WebGL, dependencias nuevas, imagenes remotas ni animacion continua. Respeta
movimiento reducido, dispositivos tactiles, visibilidad y salida de pantalla.

Todo el contenido publico se traduce a ES/EN desde translations.json; el idioma
se mantiene en query params y _vs_lang, compatible con el selector existente.
El idioma usa un selector nativo Streamlit para cambiar en la misma pagina.
El sandbox de Streamlit no permite navegacion superior desde el componente:
acceso y terminos abren una nueva pestaña mediante enlaces permitidos por el
sandbox. Navegacion por anclas, menu movil y FAQ usan elementos HTML nativos. Acceso y
registro llevan al formulario existente; terminos llevan al documento existente.
Las muestras estan identificadas como ficticias. Planes mantienen los nombres
existentes; se omiten tarifas/limites comerciales que no se pueden verificar en
Stripe y se remite a la pantalla actual. No se anuncian API, integraciones ni
garantias de deteccion no comprobadas.

Abrir desde la raiz: python -m streamlit run vulnscan.py. Visitar localhost:8501
sin parametros en una nueva pestaña/sesion para ver la presentacion. La entrada
publica no necesita credenciales. Acceder requiere la configuracion habitual.
Streamlit actual usa st.iframe con altura de contenido; se conserva un fallback
para versiones anteriores, con desplazamiento nativo dentro del componente.

Comprobaciones locales: sintaxis Python/JS, equivalencia de entradas, coincidencia
de claves ES/EN, recursos locales y ausencia de placeholders sin sustituir.
La carga publica paso AppTest sin excepciones. La captura visual en Edge headless
fallo por el proceso GPU del entorno; no se afirma una revision visual en navegador
ni una prueba manual completa de responsive, teclado o acceso autenticado.

No se modifican escaneos, facturacion, migraciones, RLS ni claves. No hubo scans,
operaciones de pago, despliegues o push. Pruebas completas de backend, Stripe test
y concurrencia quedan pendientes por decision del usuario.
