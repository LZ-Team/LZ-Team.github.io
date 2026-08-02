/** 为代码块添加复制按钮、语言角标与目录高亮 */

function enhanceCodeBlocks(scope: ParentNode): void {
  scope.querySelectorAll<HTMLElement>('pre').forEach((pre) => {
    if (pre.querySelector('.code-copy-btn')) return;

    const code = pre.querySelector('code');
    if (!code) return;

    const lang = Array.from(code.classList)
      .map((c) => c.replace(/^language-/, ''))
      .find((c) => c && c !== 'hljs');

    if (lang) {
      const badge = document.createElement('span');
      badge.className = 'code-lang';
      badge.textContent = lang;
      pre.appendChild(badge);
    }

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'code-copy-btn';
    btn.textContent = 'Copy';
    btn.addEventListener('click', async () => {
      const text = code.textContent || '';
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      btn.textContent = 'Copied';
      btn.classList.add('copied');
      window.setTimeout(() => {
        btn.textContent = 'Copy';
        btn.classList.remove('copied');
      }, 1400);
    });

    pre.appendChild(btn);
  });
}

const tocInitialized = new WeakSet<HTMLElement>();

function initToc(): void {
  const toc = document.querySelector<HTMLElement>('[data-toc]');
  const article = document.querySelector<HTMLElement>('[data-article]');
  if (!toc || !article || tocInitialized.has(toc)) return;
  tocInitialized.add(toc);

  const headings = Array.from(article.querySelectorAll<HTMLElement>('h2, h3'));
  const links = Array.from(toc.querySelectorAll<HTMLAnchorElement>('a[href^="#"]'));
  if (!headings.length || !links.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((e) => e.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (!visible) return;
      const id = (visible.target as HTMLElement).id;
      links.forEach((link) => link.classList.toggle('active', link.getAttribute('href') === `#${id}`));
    },
    { rootMargin: '-20% 0px -70% 0px' }
  );

  headings.forEach((h) => observer.observe(h));
}

/** Astro 视图过渡下，页面加载与每次导航后都会触发 */
function boot(): void {
  enhanceCodeBlocks(document);
  initToc();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}

document.addEventListener('astro:page-load', boot);
