let currentLatitude = null;
let currentLongitude = null;

// Escuchar mensajes del hilo principal (Frontend)
self.addEventListener('message', event => {
    const data = event.data;
    if (data && typeof data.latitude === 'number' && typeof data.longitude === 'number') {
        currentLatitude = data.latitude;
        currentLongitude = data.longitude;
        console.log('[SW] Ubicación recibida del frontend:', currentLatitude, currentLongitude);
    }
});

// Evento de sincronización en segundo plano (Background Sync)
self.addEventListener('sync', event => {
    if (event.tag === 'location-sync') {
        console.log('[SW] Evento de sincronización recibido: location-sync');
        event.waitUntil(syncLocationData());
    }
});

// Función para enviar datos de ubicación al servidor
async function syncLocationData() {
    if (currentLatitude != null && currentLongitude != null) {
        try {
            const response = await fetch('/update-location', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    latitude: currentLatitude,
                    longitude: currentLongitude
                })
            });

            if (!response.ok) {
                console.error('[SW] Falló la sincronización con el servidor:', response.status);
            } else {
                console.log('[SW] Ubicación sincronizada correctamente');
            }
        } catch (error) {
            console.error('[SW] Error de red durante la sincronización:', error);
        }
    } else {
        console.warn('[SW] No hay datos de ubicación para sincronizar');
    }
}

// Evento opcional para notificaciones push
self.addEventListener('push', event => {
    const data = event.data?.json();
    if (data) {
        const title = data.title || 'Nueva notificación';
        const options = {
            body: data.message || '',
            icon: '/imagenes/apk192.png'
        };
        event.waitUntil(
            self.registration.showNotification(title, options)
        );
    }
});
