// ==UserScript==
// @name         Super Anti-Popups & Anti-Redirects Ultra Pro
// @namespace    http://tampermonkey.net/
// @version      3.5
// @description  Bloqueo avanzado contra popups, popunders, iframes publicitarios y secuestro de clics (corregido).
// @author       Kevin Ortega
// @match        *://*/*
// @allFrames    true
// @run-at       document-start
// @grant        none
// @updateURL    https://raw.githubusercontent.com/kevorteg/web-privacy-shield/main/scripts/popups-block.user.js
// @downloadURL  https://raw.githubusercontent.com/kevorteg/web-privacy-shield/main/scripts/popups-block.user.js
// @license      MIT
// ==/UserScript==

(function() {
    'use strict';

    // ────────────────────────────────────────────────────────────
    // 0. LISTA BLANCA — dominios donde el script no interviene
    //    (login, pagos, bancos, etc. que dependen de popups/redirects legítimos)
    // ────────────────────────────────────────────────────────────
    const WHITELIST_DOMAINS = [
        'accounts.google.com',
        'login.microsoftonline.com',
        'appleid.apple.com',
        'paypal.com',
        'stripe.com',
        'facebook.com',
        // agrega aquí los dominios de tu banco u otros servicios de confianza
    ];

    const isWhitelisted = () =>
        WHITELIST_DOMAINS.some(d => location.hostname.endsWith(d));

    if (isWhitelisted()) {
        // No tocar nada en sitios de confianza
        return;
    }

    // Lista extendida de patrones y dominios publicitarios conocidos
    const BAD_PATTERNS = [
        'click.aliexpress.com', 'viiukuhe.com', 'reffpa.com', 'bet365', '1xbet',
        'popads', 'popcash', 'adsterra', 'exoclick', 'juicyads', 'propellerads'
    ];

    // Dominios de tiendas/afiliados que quieres bloquear explícitamente
    // aunque lleguen por redirect (agrega/quita según necesites)
    const AFFILIATE_STORE_DOMAINS = [
        'shein.com', 'aliexpress.com', 'temu.com', 'wish.com'
    ];

    // Parámetros típicos de redirects de marketing de afiliados (independiente del dominio)
    const AFFILIATE_TRACKING_PARAMS = [
        'affiliate_id', 'click_id', 'sub_id', 'campaign_id', 'onelink',
        'utm_source', 'clickid', 'aff_id', 'partner_id'
    ];

    const isBadUrl = (url) => {
        if (!url) return false;
        const strUrl = String(url).toLowerCase();

        // 1. Coincide con dominios/patrones publicitarios conocidos
        if (BAD_PATTERNS.some(pattern => strUrl.includes(pattern))) return true;

        // 2. Es una tienda de afiliados que quieres bloquear Y trae parámetros de tracking
        //    (evita falsos positivos con enlaces normales de esas tiendas sin tracking)
        const isAffiliateStore = AFFILIATE_STORE_DOMAINS.some(d => strUrl.includes(d));
        const hasTrackingParams = AFFILIATE_TRACKING_PARAMS.filter(p => strUrl.includes(p)).length >= 2;

        if (isAffiliateStore && hasTrackingParams) return true;

        return false;
    };

    // ────────────────────────────────────────────────────────────
    // 1. BLINDAJE DE WINDOW.OPEN (ya no bloquea TODO, solo lo malo)
    // ────────────────────────────────────────────────────────────
    const originalOpen = window.open.bind(window);

    const guardedOpen = function(url, target, features) {
        if (isBadUrl(url)) {
            console.warn('[Anti-Popup Ultra] Bloqueado window.open:', url);
            return null;
        }
        // Permitimos aperturas legítimas (login OAuth, "abrir en pestaña nueva", etc.)
        return originalOpen(url, target, features);
    };

    try {
        Object.defineProperty(window, 'open', {
            value: guardedOpen,
            writable: true,      // permite que otros scripts legítimos lo ajusten si es necesario
            configurable: true   // permite deshacer el parche si hace falta
        });
    } catch (e) {
        window.open = guardedOpen;
    }

    // ────────────────────────────────────────────────────────────
    // 2. PARCHEAR CREACIÓN DE IFRAMES
    // ────────────────────────────────────────────────────────────
    const originalCreateElement = document.createElement;
    document.createElement = function(tagName, options) {
        const element = originalCreateElement.call(document, tagName, options);
        if (tagName && String(tagName).toLowerCase() === 'iframe') {
            element.addEventListener('load', function() {
                try {
                    if (element.contentWindow) {
                        element.contentWindow.open = guardedOpen;
                    }
                } catch (e) {
                    // Ignorar errores de Cross-Origin
                }
            });
        }
        return element;
    };

    // ────────────────────────────────────────────────────────────
    // 3. INTERCEPTAR REDIRECCIONES EN LOCATION
    // ────────────────────────────────────────────────────────────
    try {
        const originalAssign = window.location.assign.bind(window.location);
        window.location.assign = function(url) {
            if (isBadUrl(url)) {
                console.warn('[Anti-Popup Ultra] Redirección (assign) bloqueada:', url);
                return;
            }
            return originalAssign(url);
        };

        const originalReplace = window.location.replace.bind(window.location);
        window.location.replace = function(url) {
            if (isBadUrl(url)) {
                console.warn('[Anti-Popup Ultra] Redirección (replace) bloqueada:', url);
                return;
            }
            return originalReplace(url);
        };
    } catch (e) {}

    // ────────────────────────────────────────────────────────────
    // 4. INTERCEPTAR 'CLICK' PROGRAMÁTICO EN ENLACES SOSPECHOSOS
    //    (más estricto: exige que la URL sea explícitamente mala,
    //     ya no bloquea target="_blank" sin href salvo que sea "javascript:")
    // ────────────────────────────────────────────────────────────
    const originalClick = HTMLElement.prototype.click;
    HTMLElement.prototype.click = function() {
        if (this.tagName === 'A') {
            const href = this.getAttribute('href') || '';
            if (isBadUrl(href) || href.startsWith('javascript:')) {
                console.warn('[Anti-Popup Ultra] Bloqueado .click() automático por JS:', href);
                return;
            }
        }
        return originalClick.apply(this, arguments);
    };

    // ────────────────────────────────────────────────────────────
    // 5. CAPTURA Y ANULACIÓN DE CLICS Y OVERLAYS
    //    (ahora solo en fase 'click', evita triplicar getComputedStyle)
    // ────────────────────────────────────────────────────────────
    const blockHijack = function(e) {
        let el = e.target;

        if (el && el.nodeType === Node.TEXT_NODE) {
            el = el.parentElement;
        }

        // Destruir capas/overlays transparentes maliciosas
        // (evitando romper controles de video/reproductores legítimos)
        if (el && el instanceof Element && el !== document.body && el !== document.documentElement) {
            const style = window.getComputedStyle(el);
            const isOverlay = (style.position === 'absolute' || style.position === 'fixed') && parseInt(style.zIndex, 10) > 99;
            const isTransparent = style.opacity === '0' || style.opacity === '0.01' || style.backgroundColor === 'transparent' || style.backgroundColor === 'rgba(0, 0, 0, 0)';

            if (isOverlay && isTransparent) {
                const isPlayerControl = el.closest('.vjs-control-bar, .jwplayer, .plyr, .video-js, [class*="player"]') || el.querySelector('video') || el.tagName === 'VIDEO';

                if (!isPlayerControl) {
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();
                    el.remove();
                    console.warn('[Anti-Popup Ultra] Capa transparente eliminada.');
                    return false;
                }
            }
        }
        while (el && el instanceof Element && el !== document.body) {
            if (el.hasAttribute && el.hasAttribute('onclick')) {
                const onclickVal = el.getAttribute('onclick');
                if (isBadUrl(onclickVal) || (onclickVal && onclickVal.includes('open('))) {
                    el.removeAttribute('onclick');
                }
            }

            if (el.tagName === 'A') {
                const href = el.getAttribute('href') || '';
                const target = el.getAttribute('target');

                // Solo bloqueamos si el href es explícitamente malicioso,
                // o si abre una pestaña nueva sin destino real y por JS puro (patrón típico de popunders)
                if (isBadUrl(href) || (target === '_blank' && href.startsWith('javascript:'))) {
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();
                    console.warn('[Anti-Popup Ultra] Enlace/Popup interceptado en clic:', href);
                    return false;
                }
            }
            el = el.parentElement;
        }
    };

    // Solo en fase de captura del evento 'click' (suficiente y más liviano)
    window.addEventListener('click', blockHijack, true);

})();
