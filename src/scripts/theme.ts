/** 主题切换逻辑（初始注入见 Base.astro 的 inline script，避免闪烁） */

const STORAGE_KEY = 'lz-theme';
const initialized = new WeakSet<Element>();

export function getPreferredTheme(): 'light' | 'dark' {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

export function applyTheme(theme: 'light' | 'dark'): void {
  document.documentElement.dataset.theme = theme;
}

export function initThemeToggle(): void {
  const toggle = document.querySelector<HTMLButtonElement>('[data-theme-toggle]');
  if (!toggle || initialized.has(toggle)) return;
  initialized.add(toggle);

  const label = toggle.querySelector<HTMLElement>('[data-theme-label]');

  const syncLabel = () => {
    if (label) {
      label.textContent = document.documentElement.dataset.theme === 'light' ? 'Light' : 'Dark';
    }
  };

  syncLabel();

  toggle.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    localStorage.setItem(STORAGE_KEY, next);
    applyTheme(next);
    syncLabel();
  });
}
