(() => {
  const root = document.documentElement;
  const themeButton = document.querySelector('[data-theme-toggle]');
  const menuButton = document.querySelector('[data-menu-toggle]');
  const nav = document.querySelector('[data-nav]');
  const year = document.querySelector('[data-year]');
  const toast = document.querySelector('[data-toast]');

  const savedTheme = localStorage.getItem('portfolio-theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = savedTheme || (prefersDark ? 'dark' : 'light');
  root.dataset.theme = theme;

  function updateThemeLabel() {
    if (!themeButton) return;
    const isDark = root.dataset.theme === 'dark';
    themeButton.textContent = isDark ? '☀' : '☾';
    themeButton.setAttribute('aria-label', isDark ? 'Use light theme' : 'Use dark theme');
    themeButton.title = isDark ? 'Use light theme' : 'Use dark theme';
  }

  updateThemeLabel();

  themeButton?.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('portfolio-theme', root.dataset.theme);
    updateThemeLabel();
  });

  menuButton?.addEventListener('click', () => {
    const open = nav.classList.toggle('open');
    menuButton.setAttribute('aria-expanded', String(open));
  });

  nav?.addEventListener('click', (event) => {
    if (event.target.closest('a')) {
      nav.classList.remove('open');
      menuButton?.setAttribute('aria-expanded', 'false');
    }
  });

  document.addEventListener('click', (event) => {
    if (!nav || !menuButton) return;
    if (!nav.contains(event.target) && !menuButton.contains(event.target)) {
      nav.classList.remove('open');
      menuButton.setAttribute('aria-expanded', 'false');
    }
  });

  if (year) year.textContent = new Date().getFullYear();

  window.showToast = (message) => {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    window.clearTimeout(window.__toastTimer);
    window.__toastTimer = window.setTimeout(() => toast.classList.remove('show'), 2300);
  };

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copy);
        window.showToast('Copied to clipboard');
      } catch {
        window.showToast('Copy failed. Select the text manually.');
      }
    });
  });
})();
