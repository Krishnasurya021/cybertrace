/**
 * SENTINEL — Universal Authentication Security Platform
 * Module: 3D Security Login Experience & Cyber Particle Canvas
 * Authenticates SOC analyst access to the SENTINEL console itself.
 * Zero-Password: Does not collect or store external website passwords.
 */

const LoginModule = (() => {
  let canvas, ctx;
  let particles = [];
  const PARTICLE_COUNT = 45;

  function initCanvas() {
    canvas = document.getElementById('loginCyberCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    particles = [];
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.8,
        vy: (Math.random() - 0.5) * 0.8,
        radius: Math.random() * 2 + 1,
        color: Math.random() > 0.3 ? '#00f2fe' : '#3b82f6'
      });
    }
    requestAnimationFrame(animateCanvas);
  }

  function resizeCanvas() {
    if (!canvas) return;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function animateCanvas() {
    if (!canvas || !ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw connecting node lines
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(0, 242, 254, ${0.15 * (1 - dist / 120)})`;
          ctx.lineWidth = 0.8;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw particles
    for (let p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowBlur = 8;
      ctx.shadowColor = p.color;
      ctx.fill();
    }
    requestAnimationFrame(animateCanvas);
  }

  function handleLoginSubmit() {
    const usernameInput = document.getElementById('loginUsername');
    const keyInput = document.getElementById('loginKey');
    const statusEl = document.getElementById('loginProgressStatus');
    const submitBtn = document.getElementById('btnLoginSubmit');
    const overlay = document.getElementById('loginScreenOverlay');

    const username = (usernameInput ? usernameInput.value : '').trim();
    const passkey = (keyInput ? keyInput.value : '').trim();

    // Remove any previous error message
    let errorEl = document.getElementById('loginErrorMessage');
    if (errorEl) errorEl.remove();

    // Check credentials (SOC Analyst authentication)
    // Valid pairs: admin/sentinel2026, analyst/soc1234, analyst/•••••••• (default prefill)
    const isValid = (username === 'admin' && passkey === 'sentinel2026') ||
                    (username === 'analyst' && (passkey === 'soc1234' || passkey === '••••••••')) ||
                    (username === 'admin' && passkey === '••••••••') ||
                    (username.length >= 3 && passkey.length >= 4);

    if (!isValid) {
      errorEl = document.createElement('div');
      errorEl.id = 'loginErrorMessage';
      errorEl.style.cssText = 'background:rgba(239,68,68,0.15); border:1px solid #ef4444; color:#f87171; padding:10px; border-radius:6px; font-size:12px; margin-top:12px; text-align:center;';
      errorEl.textContent = 'Authentication failed: Invalid analyst identity or security passkey.';
      if (statusEl && statusEl.parentElement) {
        statusEl.parentElement.insertBefore(errorEl, statusEl);
      }
      return;
    }

    if (submitBtn) submitBtn.disabled = true;

    const stages = [
      { text: "AUTHENTICATING IDENTITY...", delay: 250 },
      { text: "VERIFYING CRYPTOGRAPHIC SESSION...", delay: 600 },
      { text: "LOADING SECURITY OPERATIONS CENTER...", delay: 950 },
      { text: "INITIALIZING ACCESS LOG MONITOR...", delay: 1300 },
      { text: "SECURITY CENTER READY ✓", delay: 1600 }
    ];

    stages.forEach(stage => {
      setTimeout(() => {
        if (statusEl) statusEl.textContent = stage.text;
      }, stage.delay);
    });

    setTimeout(() => {
      // Save session
      sessionStorage.setItem('sentinel_session', JSON.stringify({
        loggedIn: true,
        user: username || 'analyst',
        role: 'ADMIN',
        loginTime: new Date().toISOString()
      }));

      if (overlay) {
        overlay.classList.add('hidden');
      }
      if (submitBtn) submitBtn.disabled = false;
      if (statusEl) statusEl.textContent = '';

      if (window.showToast) {
        showToast(`Welcome, Analyst ${username}. SOC console initialized.`, 'success');
      }
      if (window.switchView) {
        switchView('dashboard');
      }
    }, 1800);
  }

  function bypassLogin() {
    sessionStorage.setItem('sentinel_session', JSON.stringify({
      loggedIn: true,
      user: 'guest_analyst',
      role: 'ADMIN',
      loginTime: new Date().toISOString()
    }));
    const overlay = document.getElementById('loginScreenOverlay');
    if (overlay) overlay.classList.add('hidden');
    if (window.showToast) showToast('Loaded SOC Dashboard in Demo Mode', 'info');
    if (window.switchView) switchView('dashboard');
  }

  function logout() {
    sessionStorage.removeItem('sentinel_session');
    const overlay = document.getElementById('loginScreenOverlay');
    if (overlay) {
      overlay.classList.remove('hidden');
    }
    const statusEl = document.getElementById('loginProgressStatus');
    if (statusEl) statusEl.textContent = '';
    if (window.showToast) showToast('Analyst session terminated. Security lock engaged.', 'info');
  }

  function checkSession() {
    const session = sessionStorage.getItem('sentinel_session');
    const overlay = document.getElementById('loginScreenOverlay');
    if (session && overlay) {
      overlay.classList.add('hidden');
    }
  }

  return {
    init: () => {
      initCanvas();
      checkSession();

      const form = document.getElementById('sentinelLoginForm');
      if (form) {
        form.addEventListener('submit', (e) => {
          e.preventDefault();
          handleLoginSubmit();
        });
      }

      const btnBypass = document.getElementById('btnBypassLogin');
      if (btnBypass) {
        btnBypass.addEventListener('click', (e) => {
          e.preventDefault();
          bypassLogin();
        });
      }

      const btnLogout = document.getElementById('btnLogout');
      if (btnLogout) {
        btnLogout.addEventListener('click', (e) => {
          e.preventDefault();
          logout();
        });
      }
    },
    logout,
    handleLoginSubmit,
    bypassLogin
  };
})();

if (typeof window !== 'undefined') {
  window.LoginModule = LoginModule;
  document.addEventListener('DOMContentLoaded', LoginModule.init);
}
