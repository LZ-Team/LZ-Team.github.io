/** 右下角圆形滚动进度 + 回到顶部 */

const initialized = new WeakSet<HTMLButtonElement>();

let lastButton: HTMLButtonElement | null = null;
let lastRing: SVGCircleElement | null = null;

function update(): void {
  const scrollTop = window.scrollY;
  const docHeight = Math.max(document.documentElement.scrollHeight - window.innerHeight, 0);
  const progress = docHeight > 0 ? Math.min(scrollTop / docHeight, 1) : 0;

  if (lastRing) {
    const radius = Number(lastRing.getAttribute('r')) || 20;
    const circumference = 2 * Math.PI * radius;
    lastRing.style.strokeDasharray = String(circumference);
    lastRing.style.strokeDashoffset = String(circumference * (1 - progress));
  }

  if (lastButton) {
    lastButton.classList.toggle('visible', scrollTop > 240);
    lastButton.setAttribute('aria-label', `滚动进度 ${Math.round(progress * 100)}%，点击回到顶部`);
  }
}

export function initScrollProgress(): void {
  const button = document.querySelector<HTMLButtonElement>('[data-scroll-top]');
  if (!button) return;

  lastButton = button;
  lastRing = button.querySelector<SVGCircleElement>('[data-ring]');

  if (!initialized.has(button)) {
    initialized.add(button);
    button.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  update();
}

// scroll 监听只需注册一次
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.addEventListener('scroll', update, { passive: true });
    initScrollProgress();
  });
} else {
  window.addEventListener('scroll', update, { passive: true });
  initScrollProgress();
}

// 视图过渡导航后重新绑定新 DOM 上的按钮
document.addEventListener('astro:page-load', initScrollProgress);
