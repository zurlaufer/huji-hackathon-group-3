/**
 * AISecutity Tracker — Drop-in bot detection for any website.
 * 
 * Usage:
 *   <script src="https://your-server.com/sdk/tracker.js" 
 *           data-api-key="YOUR_API_KEY"
 *           data-endpoint="https://your-server.com/api/sdk/track">
 *   </script>
 * 
 * That's it. The script automatically:
 * - Tracks mouse movements, clicks, scrolls, keyboard
 * - Batches events every 10 seconds
 * - Sends to your AISecutity server for analysis
 * - Stores session ID in sessionStorage
 */
(function() {
  'use strict';

  // Configuration from script tag
  var script = document.currentScript;
  var API_KEY = script.getAttribute('data-api-key') || '';
  var ENDPOINT = script.getAttribute('data-endpoint') || 'http://localhost:5000/api/sdk/track';
  var BATCH_INTERVAL = parseInt(script.getAttribute('data-interval') || '10000');

  // Session
  var SESSION_ID = sessionStorage.getItem('_aisec_sid') || generateId();
  sessionStorage.setItem('_aisec_sid', SESSION_ID);

  var events = [];
  var lastMouseX = 0, lastMouseY = 0, lastMouseTime = 0;
  var lastKeyTime = 0, keyBurst = 0, keyErrors = 0, keyTotal = 0;
  var scrollY = 0;

  function generateId() {
    return 'sess-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
  }

  function record(eventType, data) {
    events.push({
      sessionId: SESSION_ID,
      userId: API_KEY,
      timestamp: new Date().toISOString(),
      eventType: eventType,
      endpoint: window.location.pathname,
      durationMs: data.duration || 0,
      mouse: data.mouse || null,
      keyboard: data.keyboard || null,
      scroll: data.scroll || null,
    });
  }

  // Mouse tracking
  var moveThrottle = 0;
  document.addEventListener('mousemove', function(e) {
    var now = Date.now();
    if (now - moveThrottle < 200) return;
    moveThrottle = now;

    var dx = e.clientX - lastMouseX;
    var dy = e.clientY - lastMouseY;
    var dist = Math.sqrt(dx*dx + dy*dy);
    var dt = now - lastMouseTime;

    if (dist > 50 && dt > 200) {
      var speed = Math.min(dist / (dt / 1000), 1200);
      var hasCurve = Math.abs(dx) > 20 && Math.abs(dy) > 20;

      record('mousemove', {
        duration: dt,
        mouse: { x: e.clientX, y: e.clientY, speed: Math.round(speed), hasCurve: hasCurve }
      });

      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
      lastMouseTime = now;
    }
  });

  // Click tracking
  document.addEventListener('click', function(e) {
    record('click', {
      duration: Date.now() - lastMouseTime,
      mouse: { x: e.clientX, y: e.clientY, speed: 500, hasCurve: true }
    });
    lastMouseTime = Date.now();
  });

  // Scroll tracking
  var scrollThrottle = 0;
  document.addEventListener('scroll', function() {
    var now = Date.now();
    if (now - scrollThrottle < 500) return;
    scrollThrottle = now;

    var newScrollY = window.scrollY || document.documentElement.scrollTop;
    var deltaY = newScrollY - scrollY;

    record('scroll', {
      duration: 200,
      mouse: { x: lastMouseX, y: lastMouseY, speed: 300, hasCurve: true },
      scroll: {
        scrollY: newScrollY,
        deltaY: deltaY,
        viewportHeight: window.innerHeight,
        pageHeight: document.documentElement.scrollHeight
      }
    });

    scrollY = newScrollY;
  });

  // Keyboard tracking
  document.addEventListener('keydown', function(e) {
    var now = Date.now();
    var dt = now - lastKeyTime;
    keyTotal++;

    if (dt < 500) keyBurst++;
    else keyBurst = 1;

    if (e.key === 'Backspace' || e.key === 'Delete') keyErrors++;

    if (keyTotal % 5 === 0) {
      record('keypress', {
        duration: dt,
        keyboard: {
          interKeyDelayMs: dt,
          burstLength: keyBurst,
          errorRate: keyTotal > 0 ? Math.round((keyErrors / keyTotal) * 100) / 100 : 0
        }
      });
    }

    lastKeyTime = now;
  });

  // Navigation tracking
  record('navigation', { duration: 0, mouse: null });

  // Batch send every N seconds
  setInterval(function() {
    if (events.length === 0) return;

    var payload = {
      apiKey: API_KEY,
      sessionId: SESSION_ID,
      userAgent: navigator.userAgent,
      url: window.location.href,
      events: events.splice(0, events.length),
    };

    // Use fetch with proper Content-Type
    fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      keepalive: true,
    }).catch(function() {});
  }, BATCH_INTERVAL);

  // Also send on page unload
  window.addEventListener('beforeunload', function() {
    if (events.length === 0) return;
    var payload = {
      apiKey: API_KEY,
      sessionId: SESSION_ID,
      userAgent: navigator.userAgent,
      url: window.location.href,
      events: events,
    };
    // sendBeacon with blob to set content-type
    var blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
    navigator.sendBeacon(ENDPOINT, blob);
  });

  console.log('[AISecutity] Tracker initialized. Session:', SESSION_ID);
})();
