# Web Privacy Shield

Suite de scripts Tampermonkey para proteger tu privacidad, bloquear fingerprinting, y defender tu navegador contra malware y rastreo.

## Autor

**Kevin Ortega** - Diseñador Multimedia & Desarrollador Web

- Portfolio: [kevinosdev.vercel.app](https://kevinosdev.vercel.app)
- GitHub: [github.com/kevorteg](https://github.com/kevorteg)
- Email: milife.ortega2000@gmail.com

## Scripts Disponibles

| Script | Version | Descripcion |
|--------|---------|-------------|
| `privacy-firewall.user.js` | v1.0 | Firewall de privacidad completo: anti-fingerprint, WebRTC protection, clipboard protection, keylogger detection |

### Proximamente

| Script | Descripcion |
|--------|------------|
| `malware-blocker.user.js` | Bloqueador de malware con deteccion DGA |
| `popups-block.user.js` | Bloqueador universal de ventanas emergentes |
| `youtube-enhancer.user.js` | Mejoras de privacidad para YouTube |
| `facebook-shield.user.js` | Proteccion de privacidad para Facebook/Instagram |

## Instalacion

### Requisitos
- [Tampermonkey](https://www.tampermonkey.net/) (Chrome, Firefox, Edge, Opera)

### Pasos
1. Haz clic en el script que quieras instalar
2. Haz clic en el boton **"Raw"**
3. Tampermonkey te preguntara si quieres instalarlo
4. Haz clic en **"Instalar"**

## Privacy Firewall - Detalles

### Anti-Fingerprinting
- **Canvas spoofing** - Inyecta ruido invisible en canvas para prevenir identificacion
- **AudioContext spoofing** - Perturba datos de audio para bloquear fingerprinting por audio
- **WebGL spoofing** - Falsifica informacion de GPU y renderer
- **ClientRects protection** - Prevenir fingerprinting por fuentes instaladas
- **Navigator spoofing** - Randomiza hardwareConcurrency, deviceMemory, platform

### WebRTC IP Leak Protection
- Bloquea IPs locales en candidates WebRTC
- Previene que tu IP real se filtre incluso con VPN
- Opcion de deshabilitar WebRTC completamente

### Clipboard Hijacking Protection
- Detecta cuando scripts modifican tu clipboard sin tu consentimiento
- Alerta especialmente si detecta cambio de direcciones crypto (BTC, ETH, SOL)
- Muestra que script intento acceder al clipboard

### Keylogger Detection
- Detecta listeners de teclado agregados por scripts de terceros
- Alerta sobre inputs ocultos (overlay keyloggers)
- Monitorea event listeners sospechosos

## Configuracion

Haz clic en el icono de Tampermonkey > Privacy Firewall > Configurar

- Activar/desactivar cada modulo individualmente
- Cambiar noise seed para fingerprinting
- Ver log de eventos bloqueados
- Modo silencioso (sin notificaciones)

## Privacidad

Estos scripts **NO** recopilan datos personales. Todo el procesamiento es 100% local en tu navegador. No hay conexiones externas, no hay telemetria, no hay tracking.

## Licencia

MIT - Usa, modifica, y comparte libremente.

---

# Web Privacy Shield (English)

Suite of Tampermonkey scripts to protect your privacy, block fingerprinting, and defend your browser against malware and tracking.

## Available Scripts

| Script | Version | Description |
|--------|---------|-------------|
| `privacy-firewall.user.js` | v1.0 | Complete privacy firewall: anti-fingerprint, WebRTC protection, clipboard protection, keylogger detection |

### Coming Soon

| Script | Description |
|--------|------------|
| `malware-blocker.user.js` | Malware blocker with DGA detection |
| `popups-block.user.js` | Universal pop-up blocker |
| `youtube-enhancer.user.js` | Privacy enhancements for YouTube |
| `facebook-shield.user.js` | Privacy protection for Facebook/Instagram |

## Installation

### Requirements
- [Tampermonkey](https://www.tampermonkey.net/) (Chrome, Firefox, Edge, Opera)

### Steps
1. Click on the script you want to install
2. Click the **"Raw"** button
3. Tampermonkey will ask if you want to install it
4. Click **"Install"**

## Privacy Firewall - Details

### Anti-Fingerprinting
- **Canvas spoofing** - Injects invisible noise into canvas to prevent identification
- **AudioContext spoofing** - Perturbs audio data to block audio fingerprinting
- **WebGL spoofing** - Fakes GPU and renderer information
- **ClientRects protection** - Prevents fingerprinting via installed fonts
- **Navigator spoofing** - Randomizes hardwareConcurrency, deviceMemory, platform

### WebRTC IP Leak Protection
- Blocks local IPs in WebRTC candidates
- Prevents your real IP from leaking even with VPN
- Option to disable WebRTC completely

### Clipboard Hijacking Protection
- Detects when scripts modify your clipboard without consent
- Alerts especially if crypto address changes detected (BTC, ETH, SOL)
- Shows which script tried to access clipboard

### Keylogger Detection
- Detects keyboard listeners added by third-party scripts
- Alerts about hidden inputs (overlay keyloggers)
- Monitors suspicious event listeners

## Privacy

These scripts **DO NOT** collect personal data. All processing is 100% local in your browser. No external connections, no telemetry, no tracking.

## License

MIT - Use, modify, and share freely.
