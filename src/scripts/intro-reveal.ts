/**
 * 首页沉浸式首屏：
 * - 首屏只显示居中的战队简介；侧边栏初始隐藏。
 * - 向下滚动超过阈值后，侧边栏浮现（body.nav-shown）。
 * - `.reveal` 元素（引导卡片区）进入视口后淡入上浮（.revealed）。
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

/** 仅在 intro（首页）模式下启用：滚动后让侧边栏浮现 */
function syncIntroNav(): void {
  if (!document.body.classList.contains('intro')) return;
  document.body.classList.toggle('nav-shown', window.scrollY > 80);
}

// scroll 监听只需注册一次
window.addEventListener('scroll', syncIntroNav, { passive: true });

function init(): void {
  setupReveals();
  syncIntroNav();
}

document.addEventListener('astro:page-load', init);

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

export function initIntroReveal(): void {
  // 幂等：由 astro:page-load 调用，逻辑已由模块级监听覆盖
}
