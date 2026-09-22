# Mis Finanzas 1.4, PIN y bloqueo automático

## Seguridad incluida
- Configuración inicial de PIN de exactamente 6 dígitos.
- PIN almacenado como hash SHA-256 con salt local, nunca en texto plano.
- Bloqueo a los 5 minutos sin actividad.
- Bloqueo inmediato al pasar la aplicación a segundo plano o apagar la pantalla.
- Botón de bloqueo manual y opción para cambiar el PIN.
- El respaldo JSON no contiene el PIN.

## Actualizar GitHub Pages existente
1. Descomprime este paquete.
2. En el repositorio `mis-finanzas`, elimina o reemplaza los archivos anteriores.
3. Sube a la raíz: `index.html`, `styles.css`, `app.js`, `manifest.webmanifest`, `service-worker.js` y la carpeta `icons`.
4. Confirma el cambio con un commit, por ejemplo: `Actualiza a versión 1.4 con PIN`.
5. GitHub Pages volverá a desplegar desde la rama configurada.
6. En el iPhone cierra la PWA y ábrela de nuevo. Si siguiera mostrando la versión anterior, elimina el icono, abre la URL en Safari y vuelve a añadirla a la pantalla de inicio.

## Nota de seguridad
El PIN es una barrera local de privacidad, no cifra los movimientos almacenados en el navegador. Un PIN de 6 dígitos puede ser objeto de prueba exhaustiva por alguien con acceso técnico completo al dispositivo o a sus datos. Para protección fuerte futura se recomienda cifrado de datos y autenticación mediante passkey/Face ID respaldada por servidor.
