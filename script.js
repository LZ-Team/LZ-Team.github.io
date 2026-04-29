const navToggle = document.querySelector('.nav-toggle');
const siteNav = document.querySelector('.site-nav');

if (navToggle && siteNav) {
    navToggle.addEventListener('click', () => {
        siteNav.classList.toggle('open');
    });
}

const typingTarget = document.querySelector('.typing');

if (typingTarget) {
    const text = typingTarget.dataset.typing || '';
    let index = 0;

    const type = () => {
        typingTarget.textContent = text.slice(0, index);
        index += 1;

        if (index <= text.length) {
            window.setTimeout(type, 42);
        }
    };

    window.setTimeout(type, 650);
}

const canvas = document.getElementById('matrix');

if (canvas) {
    const context = canvas.getContext('2d');
    const glyphs = '01{}[]<>/\\$#@LZCTFflagrootpwnshellcrypto';
    let drops = [];
    let columns = 0;
    const fontSize = 16;

    const resize = () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        columns = Math.floor(canvas.width / fontSize);
        drops = Array.from({ length: columns }, () => Math.random() * canvas.height / fontSize);
    };

    const draw = () => {
        context.fillStyle = 'rgba(3, 7, 18, 0.12)';
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.fillStyle = '#00ff9d';
        context.font = `${fontSize}px Cascadia Code, Consolas, monospace`;

        for (let i = 0; i < drops.length; i += 1) {
            const char = glyphs[Math.floor(Math.random() * glyphs.length)];
            context.fillText(char, i * fontSize, drops[i] * fontSize);

            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }

            drops[i] += 1;
        }

        window.requestAnimationFrame(draw);
    };

    resize();
    draw();
    window.addEventListener('resize', resize);
}

const filterButtons = document.querySelectorAll('[data-filter]');
const writeupCards = document.querySelectorAll('[data-card]');
const writeupSearch = document.getElementById('writeupSearch');
const emptyState = document.querySelector('.empty-state');
let activeFilter = 'all';

const applyFilters = () => {
    const keyword = (writeupSearch?.value || '').trim().toLowerCase();
    let visibleCount = 0;

    writeupCards.forEach((card) => {
        const category = card.dataset.category || '';
        const content = card.textContent.toLowerCase();
        const categoryMatched = activeFilter === 'all' || category === activeFilter;
        const keywordMatched = !keyword || content.includes(keyword);
        const visible = categoryMatched && keywordMatched;

        card.style.display = visible ? '' : 'none';

        if (visible) {
            visibleCount += 1;
        }
    });

    if (emptyState) {
        emptyState.style.display = visibleCount === 0 ? 'block' : 'none';
    }
};

filterButtons.forEach((button) => {
    button.addEventListener('click', () => {
        activeFilter = button.dataset.filter || 'all';
        filterButtons.forEach((item) => item.classList.remove('active'));
        button.classList.add('active');
        applyFilters();
    });
});

if (writeupSearch) {
    writeupSearch.addEventListener('input', applyFilters);
}
