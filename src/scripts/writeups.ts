/** Writeups 页的分类筛选与关键词搜索（全部卡片已在服务端渲染，仅做客户端过滤） */

const initialized = new WeakSet<HTMLElement>();

export function initWriteupFilters(): void {
  const root = document.querySelector<HTMLElement>('[data-writeup-toolbar]');
  const grid = document.querySelector<HTMLElement>('[data-writeup-grid]');
  const empty = document.querySelector<HTMLElement>('[data-empty-state]');
  if (!root || !grid || initialized.has(root)) return;
  initialized.add(root);

  const filterButtons = Array.from(root.querySelectorAll<HTMLButtonElement>('[data-filter]'));
  const search = root.querySelector<HTMLInputElement>('input[data-search]');

  let activeFilter = 'all';

  const apply = () => {
    const keyword = (search?.value || '').trim().toLowerCase();
    const cards = Array.from(grid.querySelectorAll<HTMLElement>('[data-card]'));
    let visibleCount = 0;

    cards.forEach((card) => {
      const cats = (card.dataset.categories || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const text = (card.textContent || '').toLowerCase();
      const matchedFilter = activeFilter === 'all' || cats.includes(activeFilter);
      const matchedSearch = !keyword || text.includes(keyword);
      const visible = matchedFilter && matchedSearch;

      card.style.display = visible ? '' : 'none';
      if (visible) visibleCount += 1;
    });

    if (empty) {
      empty.style.display = visibleCount === 0 ? 'block' : 'none';
    }
  };

  filterButtons.forEach((button) => {
    button.addEventListener('click', () => {
      activeFilter = button.dataset.filter || 'all';
      filterButtons.forEach((item) => item.classList.toggle('active', item === button));
      apply();
    });
  });

  search?.addEventListener('input', apply);
  apply();
}
