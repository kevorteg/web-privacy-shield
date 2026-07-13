// ==UserScript==
// @name         Privacy Firewall - Anti-Fingerprint & Protection
// @namespace    https://github.com/web-privacy-shield
// @version      1.0
// @description  Firewall de privacidad: anti-fingerprint, WebRTC, clipboard, keylogger detection
// @author       Kevin Ortega
// @homepage     https://kevinosdev.vercel.app
// @match        *://*/*
// @run-at       document-start
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// @grant        GM_notification
// @license      MIT
// ==/UserScript==

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════
    // CONFIGURACION
    // ═══════════════════════════════════════════════════════════════════

    const CONFIG = {
        version: '1.0',
        modules: {
            canvas: true,
            audio: true,
            webgl: true,
            clientRects: true,
            navigator: true,
            webrtc: true,
            clipboard: true,
            keylogger: true
        },
        showNotifications: true,
        notificationDuration: 4000,
        noiseIntensity: 1,
        silentMode: false
    };

    function loadConfig() {
        try {
            const saved = GM_getValue('wpf_config', null);
            if (saved) Object.assign(CONFIG, JSON.parse(saved));
        } catch(e) {}
    }

    function saveConfig() {
        try { GM_setValue('wpf_config', JSON.stringify(CONFIG)); } catch(e) {}
    }

    loadConfig();

    // ═══════════════════════════════════════════════════════════════════
    // SEED DE SESION (para fingerprinting determinista)
    // ═══════════════════════════════════════════════════════════════════

    let SESSION_SEED = GM_getValue('wpf_seed', null);
    if (!SESSION_SEED) {
        SESSION_SEED = Math.random() * 2147483647 | 0;
        GM_setValue('wpf_seed', SESSION_SEED);
    }

    function seededRandom(seed) {
        let s = seed;
        return function() {
            s = (s * 16807 + 0) % 2147483647;
            return (s - 1) / 2147483646;
        };
    }

    function generateNoise(length, intensity) {
        const rng = seededRandom(SESSION_SEED);
        const noise = new Float32Array(length);
        for (let i = 0; i < length; i++) {
            noise[i] = (rng() - 0.5) * intensity * 0.001;
        }
        return noise;
    }

    // ═══════════════════════════════════════════════════════════════════
    // ESTADO Y CONTADORES
    // ═══════════════════════════════════════════════════════════════════

    let stats = {
        canvasBlocked: 0,
        audioBlocked: 0,
        webglBlocked: 0,
        webrtcBlocked: 0,
        clipboardBlocked: 0,
        keyloggersDetected: 0,
        totalBlocked: 0
    };

    let eventLog = [];
    let notificationTimeout = null;

    // ═══════════════════════════════════════════════════════════════════
    // FUNCIONES AUXILIARES
    // ═══════════════════════════════════════════════════════════════════

    function log(type, message) {
        const entry = { type, message, time: new Date().toLocaleTimeString() };
        eventLog.unshift(entry);
        if (eventLog.length > 100) eventLog = eventLog.slice(0, 100);
        console.log('[Privacy Firewall] [' + type + '] ' + message);
    }

    // ═══════════════════════════════════════════════════════════════════
    // MODULO 1: CANVAS ANTI-FINGERPRINTING
    // ═══════════════════════════════════════════════════════════════════

    function initCanvasProtection() {
        if (!CONFIG.modules.canvas) return;

        // Proteger toDataURL
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function() {
            const ctx = this.getContext('2d');
            if (ctx) {
                const imageData = ctx.getImageData(0, 0, this.width, this.height);
                const noise = generateNoise(imageData.data.length, CONFIG.noiseIntensity);
                for (let i = 0; i < imageData.data.length; i += 4) {
                    imageData.data[i] = Math.max(0, Math.min(255,
                        imageData.data[i] + Math.round(noise[i] * 255)));
                    imageData.data[i+1] = Math.max(0, Math.min(255,
                        imageData.data[i+1] + Math.round(noise[i+1] * 255)));
                }
                const tempCanvas = document.createElement('canvas');
                tempCanvas.width = this.width;
                tempCanvas.height = this.height;
                const tempCtx = tempCanvas.getContext('2d');
                tempCtx.putImageData(imageData, 0, 0);
                stats.canvasBlocked++;
                log('CANVAS', 'Fingerprint canvas spoofed');
                return originalToDataURL.apply(tempCanvas, arguments);
            }
            return originalToDataURL.apply(this, arguments);
        };

        // Proteger toBlob
        const originalToBlob = HTMLCanvasElement.prototype.toBlob;
        HTMLCanvasElement.prototype.toBlob = function(callback) {
            const ctx = this.getContext('2d');
            if (ctx) {
                const imageData = ctx.getImageData(0, 0, this.width, this.height);
                const noise = generateNoise(imageData.data.length, CONFIG.noiseIntensity);
                for (let i = 0; i < imageData.data.length; i += 4) {
                    imageData.data[i] = Math.max(0, Math.min(255,
                        imageData.data[i] + Math.round(noise[i] * 255)));
                    imageData.data[i+1] = Math.max(0, Math.min(255,
                        imageData.data[i+1] + Math.round(noise[i+1] * 255)));
                }
                const tempCanvas = document.createElement('canvas');
                tempCanvas.width = this.width;
                tempCanvas.height = this.height;
                const tempCtx = tempCanvas.getContext('2d');
                tempCtx.putImageData(imageData, 0, 0);
                stats.canvasBlocked++;
                log('CANVAS', 'Fingerprint canvas blob spoofed');
                return originalToBlob.call(tempCanvas, callback);
            }
            return originalToBlob.apply(this, arguments);
        };

        // Proteger getContext - detectar canvas de fingerprinting
        const originalGetContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(type) {
            const ctx = originalGetContext.apply(this, arguments);
            if (ctx && type === '2d') {
                const originalMeasureText = ctx.measureText;
                ctx.measureText = function() {
                    const result = originalMeasureText.apply(this, arguments);
                    const rng = seededRandom(SESSION_SEED + (result.width || 0) * 1000);
                    result.width += (rng() - 0.5) * CONFIG.noiseIntensity * 0.01;
                    return result;
                };
            }
            return ctx;
        };

        log('MODULE', 'Canvas anti-fingerprinting activated');
    }

    // ═══════════════════════════════════════════════════════════════════
    // MODULO 2: AUDIOCONTEXT FINGERPRINT SPOOFING
    // ═══════════════════════════════════════════════════════════════════

    function initAudioProtection() {
        if (!CONFIG.modules.audio) return;

        const originalGetFloatFreqData = AnalyserNode.prototype.getFloatFrequencyData;
        AnalyserNode.prototype.getFloatFrequencyData = function(array) {
            originalGetFloatFreqData.apply(this, arguments);
            const noise = generateNoise(array.length, CONFIG.noiseIntensity * 2);
            for (let i = 0; i < array.length; i++) {
                array[i] += noise[i];
            }
            stats.audioBlocked++;
        };

        const originalGetByteFreqData = AnalyserNode.prototype.getByteFrequencyData;
        AnalyserNode.prototype.getByteFrequencyData = function(array) {
            originalGetByteFreqData.apply(this, arguments);
            const rng = seededRandom(SESSION_SEED);
            for (let i = 0; i < array.length; i++) {
                array[i] = Math.max(0, Math.min(255,
                    array[i] + Math.round((rng() - 0.5) * CONFIG.noiseIntensity * 0.5)));
            }
            stats.audioBlocked++;
        };

        const originalGetFloatTimeData = AnalyserNode.prototype.getFloatTimeDomainData;
        AnalyserNode.prototype.getFloatTimeDomainData = function(array) {
            originalGetFloatTimeData.apply(this, arguments);
            const noise = generateNoise(array.length, CONFIG.noiseIntensity);
            for (let i = 0; i < array.length; i++) {
                array[i] += noise[i];
            }
            stats.audioBlocked++;
        };

        // OfflineAudioContext fingerprint
        if (window.OfflineAudioContext) {
            const originalStartRendering = OfflineAudioContext.prototype.startRendering;
            OfflineAudioContext.prototype.startRendering = function() {
                return originalStartRendering.apply(this, arguments).then(function(buffer) {
                    for (let c = 0; c < buffer.numberOfChannels; c++) {
                        const data = buffer.getChannelData(c);
                        const noise = generateNoise(data.length, CONFIG.noiseIntensity * 3);
                        for (let i = 0; i < data.length; i++) {
                            data[i] += noise[i];
                        }
                    }
                    stats.audioBlocked++;
                    log('AUDIO', 'OfflineAudioContext fingerprint spoofed');
                    return buffer;
                });
            };
        }

        log('MODULE', 'AudioContext fingerprint spoofing activated');
    }

    // ═══════════════════════════════════════════════════════════════════
    // MODULO 3: WEBGL FINGERPRINT SPOOFING
    // ═══════════════════════════════════════════════════════════════════

    function initWebGLProtection() {
        if (!CONFIG.modules.webgl) return;

        const origGetParam = WebGLRenderingContext.prototype.getParameter;
        const origGetParam2 = (typeof WebGL2RenderingContext !== 'undefined')
            ? WebGL2RenderingContext.prototype.getParameter : null;

        const fakeParams = {
            0x1F01: 'Intel(R) UHD Graphics 630',
            0x1F00: 'Intel Inc.',
            0x8B8C: 'ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.1)',
            0x9245: 'OpenGL ES 3.0 (ANGLE 2.1.0)',
            0x1F02: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
            0x0D33: '5.0 Metal - 89.3',
            0x0D34: '5.0',
            0x0D35: 'WebGL',
            0x821B: 'WebGL 2.0 (OpenGL ES 3.0 Chromium)',
            0x821C: 'WebGL 2.0 (OpenGL ES 3.0 Chromium)',
            0x8073: 'Apple GPU',
            0x8B8D: 'ANGLE (Apple, Apple M1, OpenGL 4.1)',
            0x9246: 'ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.1)'
        };

        function patchGetParam(original) {
            return function(param) {
                if (fakeParams[param]) {
                    stats.webglBlocked++;
                    return fakeParams[param];
                }
                const result = original.apply(this, arguments);
                if (typeof result === 'string' && result.length > 50) {
                    const rng = seededRandom(SESSION_SEED + param);
                    if (rng() > 0.7) {
                        stats.webglBlocked++;
                        return result.substring(0, Math.floor(result.length * 0.8));
                    }
                }
                return result;
            };
        }

        WebGLRenderingContext.prototype.getParameter = patchGetParam(origGetParam);
        if (origGetParam2) {
            WebGL2RenderingContext.prototype.getParameter = patchGetParam(origGetParam2);
        }

        // Fingerprint debug info
        const origGetExtension = WebGLRenderingContext.prototype.getExtension;
        WebGLRenderingContext.prototype.getExtension = function(name) {
            if (name === 'WEBGL_debug_renderer_info') {
                const ext = origGetExtension.apply(this, arguments);
                if (ext) {
                    return {
                        UNMASKED_VENDOR_WEBGL: ext.UNMASKED_VENDOR_WEBGL,
                        UNMASKED_RENDERER_WEBGL: ext.UNMASKED_RENDERER_WEBGL
                    };
                }
            }
            return origGetExtension.apply(this, arguments);
        };

        log('MODULE', 'WebGL fingerprint spoofing activated');
    }

    // ═══════════════════════════════════════════════════════════════════
    // MODULO 4: CLIENTRECTS FONT FINGERPRINT PROTECTION
    // ═══════════════════════════════════════════════════════════════════

    function initClientRectsProtection() {
        if (!CONFIG.modules.clientRects) return;

        const origGetBoundingClientRect = Element.prototype.getBoundingClientRect;
        Element.prototype.getBoundingClientRect = function() {
            const rect = origGetBoundingClientRect.apply(this, arguments);
            const rng = seededRandom(SESSION_SEED + this.tagName);
            const noise = CONFIG.noiseIntensity * 0.1;
            return {
                x: rect.x + (rng() - 0.5) * noise,
                y: rect.y + (rng() - 0.5) * noise,
                width: rect.width + (rng() - 0.5) * noise,
                height: rect.height + (rng() - 0.5) * noise,
                top: rect.top + (rng() - 0.5) * noise,
                bottom: rect.bottom + (rng() - 0.5) * noise,
                left: rect.left + (rng() - 0.5) * noise,
                right: rect.right + (rng() - 0.5) * noise,
                toJSON: rect.toJSON
            };
        };

        const origGetClientRects = Element.prototype.getClientRects;
        Element.prototype.getClientRects = function() {
            const rects = origGetClientRects.apply(this, arguments);
            const rng = seededRandom(SESSION_SEED + this.tagName);
            const noise = CONFIG.noiseIntensity * 0.1;
            const newRects = [];
            for (let i = 0; i < rects.length; i++) {
                newRects.push({
                    x: rects[i].x + (rng() - 0.5) * noise,
                    y: rects[i].y + (rng() - 0.5) * noise,
                    width: rects[i].width + (rng() - 0.5) * noise,
                    height: rects[i].height + (rng() - 0.5) * noise,
                    top: rects[i].top + (rng() - 0.5) * noise,
                    bottom: rects[i].bottom + (rng() - 0.5) * noise,
                    left: rects[i].left + (rng() - 0.5) * noise,
                    right: rects[i].right + (rng() - 0.5) * noise,
                    toJSON: rects[i].toJSON
                });
            }
            return newRects;
        };

        // Range getClientRects
        const origRangeGetClientRects = Range.prototype.getClientRects;
        Range.prototype.getClientRects = function() {
            const rects = origRangeGetClientRects.apply(this, arguments);
            const rng = seededRandom(SESSION_SEED);
            const noise = CONFIG.noiseIntensity * 0.1;
            const newRects = [];
            for (let i = 0; i < rects.length; i++) {
                newRects.push({
                    x: rects[i].x + (rng() - 0.5) * noise,
                    y: rects[i].y + (rng() - 0.5) * noise,
                    width: rects[i].width + (rng() - 0.5) * noise,
                    height: rects[i].height + (rng() - 0.5) * noise,
                    top: rects[i].top + (rng() - 0.5) * noise,
                    bottom: rects[i].bottom + (rng() - 0.5) * noise,
                    left: rects[i].left + (rng() - 0.5) * noise,
                    right: rects[i].right + (rng() - 0.5) * noise,
                    toJSON: rects[i].toJSON
                });
            }
            return newRects;
        };

        log('MODULE', 'ClientRects font fingerprint protection activated');
    }

    // ═══════════════════════════════════════════════════════════════════
    // MODULO 5: NAVIGATOR SPOOFING
    // ═══════════════════════════════════════════════════════════════════

    function initNavigatorProtection() {
        if (!CONFIG.modules.navigator) return;

        const rng = seededRandom(SESSION_SEED);

        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: function() { return 4 + Math.floor(rng() * 5); },
            configurable: true
        });

        Object.defineProperty(navigator, 'deviceMemory', {
            get: function() { return [2, 4, 8, 16][Math.floor(rng() * 4)]; },
            configurable: true
        });

        const platforms = ['Win32', 'Linux x86_64', 'MacIntel'];
        Object.defineProperty(navigator, 'platform', {
            get: function() { return platforms[Math.floor(rng() * platforms.length)]; },
            configurable: true
        });

        Object.defineProperty(navigator, 'maxTouchPoints', {
            get: function() { return 0; },
            configurable: true
        });

        log('MODULE', 'Navigator property spoofing activated');
    }

    // ═══════════════════════════════════════════════════════════════════
    // MODULO 6: WEBRTC IP LEAK PROTECTION
    // ═══════════════════════════════════════════════════════════════════

    function initWebRTCProtection() {
        if (!CONFIG.modules.webrtc) return;

        if (!window.RTCPeerConnection && !window.webkitRTCPeerConnection) {
            log('WEBRTC', 'RTCPeerConnection not available');
            return;
        }

        const RTCPeerConstructor = window.RTCPeerConnection || window.webkitRTCPeerConnection;

        const OrigRTC = RTCPeerConstructor;

        window.RTCPeerConnection = function(config) {
            if (config && config.iceServers) {
                config.iceServers = [];
            }
            const pc = new OrigRTC(config);

            const origAddIce = pc.addIceCandidate;
            pc.addIceCandidate = function(candidate) {
                if (candidate && candidate.candidate) {
                    const c = candidate.candidate;
                    if (c.includes('192.168.') || c.includes('10.') ||
                        c.includes('172.16.') || c.includes('172.17.') ||
                        c.includes('172.18.') || c.includes('172.19.') ||
                        c.includes('172.2') || c.includes('172.30.') ||
                        c.includes('172.31.') || c.includes('127.0.') ||
                        c.includes('0.0.0.0') || c.includes('::1') ||
                        c.includes('fd') || c.includes('fe80:')) {
                        stats.webrtcBlocked++;
                        log('WEBRTC', 'Local IP candidate blocked: ' + c.substring(0, 50));
                        return Promise.resolve();
                    }
                }
                return origAddIce.apply(this, arguments);
            };

            const origCreateOffer = pc.createOffer;
            pc.createOffer = function() {
                return origCreateOffer.apply(this, arguments).then(function(offer) {
                    if (offer && offer.sdp) {
                        offer.sdp = offer.sdp.replace(/a=candidate:\d+ \d+ udp \d+ ([0-9.]+).*/g,
                            function(match, ip) {
                                if (ip.startsWith('192.168.') || ip.startsWith('10.') ||
                                    ip.startsWith('172.') || ip.startsWith('127.')) {
                                    stats.webrtcBlocked++;
                                    log('WEBRTC', 'SDP local IP stripped: ' + ip);
                                    return '';
                                }
                                return match;
                            }
                        );
                    }
                    return offer;
                });
            };

            log('WEBRTC', 'RTCPeerConnection patched for IP leak protection');
            return pc;
        };

        window.RTCPeerConnection.prototype = OrigRTC.prototype;

        log('MODULE', 'WebRTC IP leak protection activated');
    }

    // ═══════════════════════════════════════════════════════════════════
    // MODULO 7: CLIPBOARD HIJACKING PROTECTION
    // ═══════════════════════════════════════════════════════════════════

    function initClipboardProtection() {
        if (!CONFIG.modules.clipboard) return;

        const btcPattern = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/;
        const ethPattern = /\b0x[0-9a-fA-F]{40}\b/;
        const solPattern = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/;

        function isCryptoAddress(text) {
            return btcPattern.test(text) || ethPattern.test(text) || solPattern.test(text);
        }

        // Proteger execCommand('copy')
        const origExecCommand = document.execCommand;
        document.execCommand = function(cmd) {
            if (cmd === 'copy') {
                const sel = window.getSelection();
                const text = sel ? sel.toString() : '';
                log('CLIPBOARD', 'Copy command intercepted: ' + text.substring(0, 30) + '...');
                stats.clipboardBlocked++;
            }
            return origExecCommand.apply(this, arguments);
        };

        // Proteger Clipboard API
        if (navigator.clipboard && navigator.clipboard.writeText) {
            const origWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
            navigator.clipboard.writeText = function(text) {
                if (isCryptoAddress(text)) {
                    stats.clipboardBlocked++;
                    log('CLIPBOARD', 'Crypto address clipboard write detected: ' + text.substring(0, 10) + '...');
                    showNotification('CLIPBOARD', 'Crypto address detected in clipboard write!');
                    return Promise.resolve();
                }
                log('CLIPBOARD', 'WriteText: ' + text.substring(0, 30));
                stats.clipboardBlocked++;
                return origWriteText(text);
            };
        }

        // Proteger paste
        const origPaste = document.execCommand.bind(document);
        document.addEventListener('paste', function(e) {
            const text = e.clipboardData ? e.clipboardData.getData('text') : '';
            if (isCryptoAddress(text)) {
                log('CLIPBOARD', 'Crypto address in paste detected!');
                showNotification('CLIPBOARD', 'Warning: Crypto address in clipboard!');
            }
        }, true);

        log('MODULE', 'Clipboard hijacking protection activated');
    }

    // ═══════════════════════════════════════════════════════════════════
    // MODULO 8: KEYLOGGER DETECTION
    // ═══════════════════════════════════════════════════════════════════

    function initKeyloggerDetection() {
        if (!CONFIG.modules.keylogger) return;

        const suspiciousEvents = ['keydown', 'keyup', 'keypress', 'input', 'change'];
        const knownScripts = new Set();
        const scriptListeners = new Map();

        // Hook addEventListener
        const origAddEventListener = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            if (suspiciousEvents.includes(type) && this !== document && this !== window) {
                const stack = new Error().stack;
                const scriptMatch = stack.match(/at\s+(https?:\/\/[^\s:]+)/);
                const scriptUrl = scriptMatch ? scriptMatch[1] : 'inline';

                if (scriptUrl !== 'inline' && !scriptUrl.includes(window.location.hostname)) {
                    if (!scriptListeners.has(scriptUrl)) {
                        scriptListeners.set(scriptUrl, []);
                    }
                    scriptListeners.get(scriptUrl).push(type);

                    if (!knownScripts.has(scriptUrl)) {
                        knownScripts.add(scriptUrl);
                        stats.keyloggersDetected++;
                        log('KEYLOGGER', 'Third-party keyboard listener detected: ' + scriptUrl);
                        showNotification('KEYLOGGER',
                            'Suspicious keyboard listener from: ' + scriptUrl.substring(0, 40));
                    }
                }
            }
            return origAddEventListener.apply(this, arguments);
        };

        // Hook document.onkeydown assignments
        const origDefineProperty = Object.defineProperty;
        const documentProto = Document.prototype;

        ['onkeydown', 'onkeyup', 'keypress'].forEach(function(prop) {
            const desc = Object.getOwnPropertyDescriptor(documentProto, prop) ||
                         Object.getOwnPropertyDescriptor(HTMLDocument.prototype, prop);
            if (desc) {
                origDefineProperty(documentProto, prop, {
                    get: function() {
                        return desc.get.apply(this, arguments);
                    },
                    set: function(fn) {
                        if (fn) {
                            const stack = new Error().stack;
                            const scriptMatch = stack.match(/at\s+(https?:\/\/[^\s:]+)/);
                            if (scriptMatch) {
                                stats.keyloggersDetected++;
                                log('KEYLOGGER', 'Direct ' + prop + ' assignment from: ' + scriptMatch[1]);
                            }
                        }
                        return desc.set.apply(this, arguments);
                    },
                    configurable: true
                });
            }
        });

        // Detect overlay keyloggers (hidden inputs)
        function detectOverlays() {
            document.querySelectorAll('input, textarea').forEach(function(el) {
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                if ((style.position === 'fixed' || style.position === 'absolute') &&
                    (rect.width === 0 || rect.height === 0 ||
                     style.opacity === '0' || style.visibility === 'hidden' ||
                     style.zIndex > 999999)) {
                    stats.keyloggersDetected++;
                    log('KEYLOGGER', 'Potential overlay input detected: ' + el.outerHTML.substring(0, 50));
                    showNotification('KEYLOGGER', 'Hidden input overlay detected!');
                    el.remove();
                }
            });
        }

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', detectOverlays);
        } else {
            detectOverlays();
        }

        const overlayObserver = new MutationObserver(function(mutations) {
            mutations.forEach(function(m) {
                if (m.addedNodes.length > 0) {
                    setTimeout(detectOverlays, 100);
                }
            });
        });

        if (document.documentElement) {
            overlayObserver.observe(document.documentElement, {
                childList: true, subtree: true
            });
        }

        log('MODULE', 'Keylogger detection activated');
    }

    // ═══════════════════════════════════════════════════════════════════
    // UI - BADGE FLOTANTE
    // ═══════════════════════════════════════════════════════════════════

    function createStyles() {
        if (document.getElementById('wpf-styles')) return;
        const s = document.createElement('style');
        s.id = 'wpf-styles';
        s.textContent = `
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
            #wpf-badge{position:fixed;bottom:20px;right:20px;z-index:2147483647;font-family:'Inter',system-ui,sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:16px 20px;min-width:280px;max-width:340px;box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 40px rgba(34,211,238,.05);opacity:0;transform:translateY(20px) scale(.95);transition:all .4s cubic-bezier(.4,0,.2,1);pointer-events:none}
            #wpf-badge.visible{opacity:1;transform:translateY(0) scale(1);pointer-events:auto}
            .wpf-header{display:flex;align-items:center;gap:10px;margin-bottom:12px}
            .wpf-icon{width:36px;height:36px;background:linear-gradient(135deg,#06b6d4,#0891b2);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 4px 12px rgba(6,182,212,.3)}
            .wpf-title{color:#f1f5f9;font-size:14px;font-weight:600}
            .wpf-subtitle{color:#64748b;font-size:11px}
            .wpf-close{margin-left:auto;background:rgba(255,255,255,.06);border:none;color:#64748b;width:24px;height:24px;border-radius:6px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:12px;transition:all .2s}
            .wpf-close:hover{background:rgba(239,68,68,.15);color:#ef4444}
            .wpf-modules{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:12px}
            .wpf-module{display:flex;align-items:center;gap:6px;padding:6px 8px;background:rgba(255,255,255,.04);border-radius:8px;border:1px solid rgba(255,255,255,.05)}
            .wpf-module-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
            .wpf-module-dot.active{background:#22c55e;box-shadow:0 0 8px rgba(34,197,94,.4)}
            .wpf-module-dot.inactive{background:#ef4444}
            .wpf-module-name{color:#cbd5e1;font-size:10px;font-weight:500}
            .wpf-stats{background:rgba(255,255,255,.04);border-radius:10px;padding:10px 12px;margin-bottom:12px}
            .wpf-stat-row{display:flex;align-items:center;justify-content:space-between;padding:4px 0}
            .wpf-stat-label{color:#94a3b8;font-size:11px}
            .wpf-stat-value{color:#06b6d4;font-size:13px;font-weight:700;font-family:'JetBrains Mono',monospace}
            .wpf-stat-value.danger{color:#ef4444}
            .wpf-footer{display:flex;gap:8px}
            .wpf-btn{flex:1;padding:8px;border:none;border-radius:8px;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;font-family:'Inter',system-ui,sans-serif}
            .wpf-btn-primary{background:linear-gradient(135deg,#06b6d4,#0891b2);color:white}
            .wpf-btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(6,182,212,.4)}
            .wpf-btn-secondary{background:rgba(255,255,255,.06);color:#94a3b8}
            .wpf-btn-secondary:hover{background:rgba(255,255,255,.1);color:#fff}
            #wpf-config-panel{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%) scale(.9);z-index:2147483647;background:linear-gradient(135deg,#0f172a,#1e293b);border:1px solid rgba(255,255,255,.1);border-radius:20px;padding:24px;width:380px;max-height:80vh;overflow-y:auto;box-shadow:0 30px 80px rgba(0,0,0,.6);opacity:0;pointer-events:none;transition:all .3s cubic-bezier(.4,0,.2,1)}
            #wpf-config-panel.visible{opacity:1;transform:translate(-50%,-50%) scale(1);pointer-events:auto}
            .wpf-config-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:2147483646;opacity:0;pointer-events:none;transition:opacity .3s}
            .wpf-config-overlay.visible{opacity:1;pointer-events:auto}
            .wpf-config-title{color:#f1f5f9;font-size:18px;font-weight:700;margin-bottom:20px;display:flex;align-items:center;gap:10px}
            .wpf-config-section{margin-bottom:16px}
            .wpf-config-label{color:#64748b;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;display:block}
            .wpf-config-toggle{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:rgba(255,255,255,.04);border-radius:10px;margin-bottom:6px}
            .wpf-config-toggle-label{color:#e2e8f0;font-size:13px}
            .wpf-toggle{width:40px;height:22px;background:rgba(255,255,255,.1);border-radius:11px;position:relative;cursor:pointer;transition:background .2s}
            .wpf-toggle.active{background:#06b6d4}
            .wpf-toggle::after{content:'';position:absolute;top:2px;left:2px;width:18px;height:18px;background:white;border-radius:50%;transition:transform .2s}
            .wpf-toggle.active::after{transform:translateX(18px)}
            .wpf-config-footer{display:flex;gap:10px;margin-top:20px}
            .wpf-config-btn{flex:1;padding:12px;border:none;border-radius:10px;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;font-family:'Inter',system-ui,sans-serif}
            .wpf-config-btn-save{background:linear-gradient(135deg,#06b6d4,#0891b2);color:white}
            .wpf-config-btn-cancel{background:rgba(255,255,255,.06);color:#94a3b8}
            @keyframes wpf-pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.05)}}
            .wpf-pulse{animation:wpf-pulse .3s ease-in-out}
        `;
        document.head.appendChild(s);
    }

    function createBadge() {
        if (document.getElementById('wpf-badge')) return;

        const badge = document.createElement('div');
        badge.id = 'wpf-badge';
        badge.innerHTML = `
            <div class="wpf-header">
                <div class="wpf-icon">🛡️</div>
                <div>
                    <div class="wpf-title">Privacy Firewall</div>
                    <div class="wpf-subtitle">v${CONFIG.version} - Protegiendo</div>
                </div>
                <button class="wpf-close" id="wpf-close">✕</button>
            </div>
            <div class="wpf-modules" id="wpf-modules"></div>
            <div class="wpf-stats">
                <div class="wpf-stat-row">
                    <span class="wpf-stat-label">Elementos protegidos</span>
                    <span class="wpf-stat-value danger" id="wpf-total">0</span>
                </div>
                <div class="wpf-stat-row">
                    <span class="wpf-stat-label">Keyloggers detectados</span>
                    <span class="wpf-stat-value" id="wpf-keyloggers">0</span>
                </div>
            </div>
            <div class="wpf-footer">
                <button class="wpf-btn wpf-btn-secondary" id="wpf-config-btn">⚙️ Config</button>
                <button class="wpf-btn wpf-btn-primary" id="wpf-log-btn">📊 Ver Log</button>
            </div>`;
        document.body.appendChild(badge);

        document.getElementById('wpf-close').onclick = function() {
            badge.classList.remove('visible');
        };
        document.getElementById('wpf-config-btn').onclick = showConfigPanel;
        document.getElementById('wpf-log-btn').onclick = showEventLog;

        updateModulesDisplay();

        setTimeout(function() {
            badge.classList.add('visible');
        }, 800);
    }

    function updateModulesDisplay() {
        const el = document.getElementById('wpf-modules');
        if (!el) return;

        const modules = [
            { key: 'canvas', name: 'Canvas' },
            { key: 'audio', name: 'Audio' },
            { key: 'webgl', name: 'WebGL' },
            { key: 'clientRects', name: 'Fonts' },
            { key: 'navigator', name: 'Navigator' },
            { key: 'webrtc', name: 'WebRTC' },
            { key: 'clipboard', name: 'Clipboard' },
            { key: 'keylogger', name: 'Keylogger' }
        ];

        el.innerHTML = modules.map(function(m) {
            const active = CONFIG.modules[m.key];
            return `<div class="wpf-module">
                <div class="wpf-module-dot ${active ? 'active' : 'inactive'}"></div>
                <div class="wpf-module-name">${m.name}</div>
            </div>`;
        }).join('');
    }

    function updateBadge() {
        const total = stats.canvasBlocked + stats.audioBlocked + stats.webglBlocked +
                     stats.webrtcBlocked + stats.clipboardBlocked;
        const totalEl = document.getElementById('wpf-total');
        const keyloggersEl = document.getElementById('wpf-keyloggers');

        if (totalEl) {
            totalEl.textContent = total;
            if (total > 0) {
                totalEl.parentElement.classList.add('wpf-pulse');
                setTimeout(function() {
                    totalEl.parentElement.classList.remove('wpf-pulse');
                }, 300);
            }
        }
        if (keyloggersEl) {
            keyloggersEl.textContent = stats.keyloggersDetected;
        }
    }

    function showNotification(type, message) {
        if (!CONFIG.showNotifications || CONFIG.silentMode) return;

        createStyles();
        createBadge();
        updateBadge();

        if (notificationTimeout) clearTimeout(notificationTimeout);
        notificationTimeout = setTimeout(function() {
            var badge = document.getElementById('wpf-badge');
            if (badge) badge.classList.remove('visible');
        }, CONFIG.notificationDuration);
    }

    // ═══════════════════════════════════════════════════════════════════
    // PANEL DE LOG DE EVENTOS
    // ═══════════════════════════════════════════════════════════════════

    function showEventLog() {
        const logWindow = window.open('', '_blank', 'width=700,height=500');
        if (!logWindow) {
            alert('Permitir pop-ups para ver el log');
            return;
        }

        const html = `<!DOCTYPE html>
<html><head><title>Privacy Firewall - Event Log</title>
<style>
body{font-family:'Inter',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px;margin:0}
h1{font-size:20px;margin-bottom:20px;color:#06b6d4}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:20px}
.stat{background:rgba(255,255,255,.05);border-radius:8px;padding:12px;text-align:center}
.stat-value{font-size:24px;font-weight:700;color:#06b6d4;font-family:'JetBrains Mono',monospace}
.stat-label{font-size:10px;color:#64748b;text-transform:uppercase}
.log-list{max-height:350px;overflow-y:auto}
.log-entry{display:flex;align-items:center;gap:12px;padding:8px 12px;border-radius:6px;margin-bottom:4px;background:rgba(255,255,255,.03)}
.log-time{color:#64748b;font-size:10px;font-family:'JetBrains Mono',monospace;min-width:80px}
.log-type{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;min-width:70px;text-align:center}
.log-type.CANVAS{background:rgba(168,85,247,.2);color:#a855f7}
.log-type.AUDIO{background:rgba(34,197,94,.2);color:#22c55e}
.log-type.WEBGL{background:rgba(251,191,36,.2);color:#fbbf24}
.log-type.WEBRTC{background:rgba(239,68,68,.2);color:#ef4444}
.log-type.CLIPBOARD{background:rgba(6,182,212,.2);color:#06b6d4}
.log-type.KEYLOGGER{background:rgba(239,68,68,.3);color:#ef4444}
.log-type.MODULE{background:rgba(59,130,246,.2);color:#3b82f6}
.log-msg{color:#cbd5e1;font-size:12px;flex:1}
</style></head><body>
<h1>🛡️ Privacy Firewall - Event Log</h1>
<div class="stats">
<div class="stat"><div class="stat-value">${stats.canvasBlocked}</div><div class="stat-label">Canvas</div></div>
<div class="stat"><div class="stat-value">${stats.audioBlocked}</div><div class="stat-label">Audio</div></div>
<div class="stat"><div class="stat-value">${stats.webglBlocked}</div><div class="stat-label">WebGL</div></div>
<div class="stat"><div class="stat-value">${stats.webrtcBlocked}</div><div class="stat-label">WebRTC</div></div>
<div class="stat"><div class="stat-value">${stats.clipboardBlocked}</div><div class="stat-label">Clipboard</div></div>
<div class="stat"><div class="stat-value">${stats.keyloggersDetected}</div><div class="stat-label">Keyloggers</div></div>
<div class="stat"><div class="stat-value">${SESSION_SEED}</div><div class="stat-label">Session Seed</div></div>
<div class="stat"><div class="stat-value">${eventLog.length}</div><div class="stat-label">Events</div></div>
</div>
<h2 style="font-size:14px;color:#94a3b8">Eventos recientes</h2>
<div class="log-list">
${eventLog.map(function(e) {
    return '<div class="log-entry"><span class="log-time">' + e.time +
           '</span><span class="log-type ' + e.type + '">' + e.type +
           '</span><span class="log-msg">' + e.message + '</span></div>';
}).join('')}
</div></body></html>`;

        logWindow.document.write(html);
        logWindow.document.close();
    }

    // ═══════════════════════════════════════════════════════════════════
    // PANEL DE CONFIGURACION
    // ═══════════════════════════════════════════════════════════════════

    function showConfigPanel() {
        let overlay = document.getElementById('wpf-config-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'wpf-config-overlay';
            overlay.className = 'wpf-config-overlay';
            document.body.appendChild(overlay);
        }

        let panel = document.getElementById('wpf-config-panel');
        if (!panel) {
            panel = document.createElement('div');
            panel.id = 'wpf-config-panel';
            document.body.appendChild(panel);
        }

        const moduleNames = {
            canvas: 'Canvas Anti-Fingerprint',
            audio: 'AudioContext Spoofing',
            webgl: 'WebGL Fingerprint',
            clientRects: 'ClientRects Protection',
            navigator: 'Navigator Spoofing',
            webrtc: 'WebRTC IP Leak Protection',
            clipboard: 'Clipboard Hijacking Protection',
            keylogger: 'Keylogger Detection'
        };

        panel.innerHTML = `
            <div class="wpf-config-title">⚙️ Privacy Firewall Config</div>
            <div class="wpf-config-section">
                <span class="wpf-config-label">Modulos de proteccion</span>
                ${Object.keys(CONFIG.modules).map(function(key) {
                    return `<div class="wpf-config-toggle">
                        <span class="wpf-config-toggle-label">${moduleNames[key]}</span>
                        <div class="wpf-toggle ${CONFIG.modules[key] ? 'active' : ''}" data-module="${key}"></div>
                    </div>`;
                }).join('')}
            </div>
            <div class="wpf-config-section">
                <span class="wpf-config-label">Opciones</span>
                <div class="wpf-config-toggle">
                    <span class="wpf-config-toggle-label">Mostrar notificaciones</span>
                    <div class="wpf-toggle ${CONFIG.showNotifications ? 'active' : ''}" id="wpf-toggle-notif"></div>
                </div>
                <div class="wpf-config-toggle">
                    <span class="wpf-config-toggle-label">Modo silencioso</span>
                    <div class="wpf-toggle ${CONFIG.silentMode ? 'active' : ''}" id="wpf-toggle-silent"></div>
                </div>
            </div>
            <div class="wpf-config-footer">
                <button class="wpf-config-btn wpf-config-btn-cancel" id="wpf-config-cancel">Cancelar</button>
                <button class="wpf-config-btn wpf-config-btn-save" id="wpf-config-save">Guardar</button>
            </div>`;

        panel.querySelectorAll('.wpf-toggle[data-module]').forEach(function(toggle) {
            toggle.addEventListener('click', function() {
                this.classList.toggle('active');
            });
        });

        document.getElementById('wpf-toggle-notif').addEventListener('click', function() {
            this.classList.toggle('active');
        });
        document.getElementById('wpf-toggle-silent').addEventListener('click', function() {
            this.classList.toggle('active');
        });

        document.getElementById('wpf-config-cancel').onclick = hideConfigPanel;

        document.getElementById('wpf-config-save').addEventListener('click', function() {
            panel.querySelectorAll('.wpf-toggle[data-module]').forEach(function(toggle) {
                const module = toggle.dataset.module;
                CONFIG.modules[module] = toggle.classList.contains('active');
            });

            CONFIG.showNotifications = document.getElementById('wpf-toggle-notif').classList.contains('active');
            CONFIG.silentMode = document.getElementById('wpf-toggle-silent').classList.contains('active');

            saveConfig();
            hideConfigPanel();
            updateModulesDisplay();
        });

        overlay.classList.add('visible');
        panel.classList.add('visible');
    }

    function hideConfigPanel() {
        const overlay = document.getElementById('wpf-config-overlay');
        const panel = document.getElementById('wpf-config-panel');
        if (overlay) overlay.classList.remove('visible');
        if (panel) panel.classList.remove('visible');
    }

    // ═══════════════════════════════════════════════════════════════════
    // DETECCION DE SCRIPTS NUEVOS (MutationObserver)
    // ═══════════════════════════════════════════════════════════════════

    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.addedNodes.length > 0) {
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === 1) {
                        if (node.tagName === 'SCRIPT' && node.src) {
                            const url = node.src;
                            if (!url.includes(window.location.hostname) &&
                                !url.includes('googleapis.com') &&
                                !url.includes('gstatic.com') &&
                                !url.includes('cloudflare.com')) {
                                log('SCRIPT', 'New third-party script: ' + url.substring(0, 60));
                            }
                        }
                    }
                });
            }
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    // INICIALIZACION
    // ═══════════════════════════════════════════════════════════════════

    function init() {
        createStyles();

        initCanvasProtection();
        initAudioProtection();
        initWebGLProtection();
        initClientRectsProtection();
        initNavigatorProtection();
        initWebRTCProtection();
        initClipboardProtection();
        initKeyloggerDetection();

        if (document.documentElement) {
            observer.observe(document.documentElement, {
                childList: true,
                subtree: true
            });
        }

        const activeModules = Object.values(CONFIG.modules).filter(Boolean).length;
        console.log('[Privacy Firewall] v' + CONFIG.version + ' active');
        console.log('[Privacy Firewall] Modules active: ' + activeModules + '/8');
        console.log('[Privacy Firewall] Session seed: ' + SESSION_SEED);

        createBadge();
        setTimeout(function() {
            updateBadge();
        }, 1000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // ═══════════════════════════════════════════════════════════════════
    // MENU TAMPERMONKEY
    // ═══════════════════════════════════════════════════════════════════

    GM_registerMenuCommand('⚙️ Configurar', showConfigPanel);
    GM_registerMenuCommand('📊 Ver Log', showEventLog);
    GM_registerMenuCommand('🔄 Nueva Session Seed', function() {
        SESSION_SEED = Math.random() * 2147483647 | 0;
        GM_setValue('wpf_seed', SESSION_SEED);
        alert('Nueva session seed generada: ' + SESSION_SEED);
    });

})();
