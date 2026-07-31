/** 轻量矩阵雨背景 —— 作为氛围层，低调且性能友好。返回清理函数。 */

export function initMatrix(canvas: HTMLCanvasElement | null): (() => void) | null {
  if (!canvas) return null;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return null;

  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  const glyphs = '01{}[]<>/\\$#@LZCTFflagrootpwnshellcrypto';
  let drops: number[] = [];
  let columns = 0;
  let rafId = 0;
  const fontSize = 15;

  const resize = () => {
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.floor(window.innerWidth * dpr);
    canvas.height = Math.floor(window.innerHeight * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    columns = Math.floor(window.innerWidth / fontSize);
    drops = Array.from({ length: columns }, () => (Math.random() * window.innerHeight) / fontSize);
  };

  const draw = () => {
    ctx.fillStyle = 'rgba(5, 7, 13, 0.10)';
    ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);
    ctx.fillStyle = '#34d399';
    ctx.font = `${fontSize}px "JetBrains Mono", Consolas, monospace`;

    for (let i = 0; i < drops.length; i += 1) {
      const char = glyphs[Math.floor(Math.random() * glyphs.length)];
      ctx.fillText(char, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > window.innerHeight && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i] += 1;
    }

    rafId = window.requestAnimationFrame(draw);
  };

  const onVisibility = () => {
    if (document.hidden) {
      window.cancelAnimationFrame(rafId);
      rafId = 0;
    } else if (!rafId) {
      draw();
    }
  };

  resize();
  draw();

  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', onVisibility);

  return () => {
    window.cancelAnimationFrame(rafId);
    rafId = 0;
    window.removeEventListener('resize', resize);
    document.removeEventListener('visibilitychange', onVisibility);
  };
}
