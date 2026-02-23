/**
 * main.js
 * Minimal client-side JavaScript for the Network Monitor UI.
 * Section 3.4.7 — no external API dependencies.
 * All data originates from the internal backend.
 */

// Auto-dismiss flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function () {
    const flashes = document.querySelectorAll('.flash');
    flashes.forEach(function (el) {
        setTimeout(function () {
            el.style.transition = 'opacity 0.4s';
            el.style.opacity = '0';
            setTimeout(function () { el.remove(); }, 400);
        }, 5000);
    });
});
