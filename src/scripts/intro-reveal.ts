/**
 * 首页沉浸式首屏：
 * - `.reveal` 元素（引导卡片区）进入视口后淡入上浮（.revealed）。
 * - 首页不使用侧边栏，故不再有滚动浮现逻辑。
 */

const observed = new WeakSet<Element>();

function setupReveals(): void {
  document.querySelectorAll<HTMLElement>('.reveal').forEach((el) => {
    if (observed.has(el)) return;
    observed.add(el);
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('revealed');
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15, rootMargin: '0px 0px -48px 0px' }
    );
    io.observe(el);
  });
}

function init(): void {
  setupReveals();
}

document.addEventListener('astro:page-load', init);

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
