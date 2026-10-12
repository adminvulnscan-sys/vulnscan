# Retorno de Checkout — 2026-10-13

La pestaña autenticada conserva la referencia de la ventana que abre al comprar.
Cuando esa ventana vuelve al mismo origen con el identificador de Checkout
esperado, la pestaña creadora la cierra y recupera el foco. No se transfieren
credenciales ni se conceden derechos desde los parámetros de retorno. El saldo
continúa dependiendo del webhook y de la consulta autenticada al servidor.

Se retiraron los documentos y mensajes intermedios de apertura y retorno. Durante
la creación de Checkout se añade un indicador dentro del botón. Los módulos de
navegación y sincronización se recargan al actualizar la aplicación para evitar
conservar los componentes de una versión anterior.

Verificado en Chrome sobre la aplicación publicada, ejecutando el mecanismo local
corregido: una ventana externa volvió con un identificador ficticio, se cerró y
el panel original permaneció autenticado y visible. No se abrió Checkout ni se
realizó una compra en esta comprobación. La versión anterior recibía la
notificación, pero el iframe de retorno no conseguía cerrar su ventana superior.

Pruebas automatizadas: 84 pruebas Python y 14 pruebas JavaScript aprobadas;
arranque comprobado también con módulos previamente importados.

Pendiente: comprobar el recorrido completo tras un pago real en Stripe test.
La prueba de navegador anterior comprueba el mecanismo de retorno, no ese
recorrido completo. Si se cierra la pestaña original o se abre el retorno en otro
navegador, es necesario iniciar sesión: la URL nunca autentica por sí sola.
El navegador conserva el control sobre el foco y los bloqueos de ventanas.
