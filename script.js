const siteData = window.LZ_SITE_DATA || {};

const escapeHtml = (value = '') => String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

const navToggle = document.querySelector('.nav-toggle');
const siteNav = document.querySelector('.site-nav');

if (navToggle && siteNav) {
    navToggle.addEventListener('click', () => {
        siteNav.classList.toggle('open');
    });
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

const tagClass = (category = '') => category.toLowerCase();

const postCard = (post) => `
    <a class="card" data-card data-category="${escapeHtml(post.category)}" href="post.html?post=${encodeURIComponent(post.slug)}">
        <span class="tag ${tagClass(post.category)}">${escapeHtml(post.category).toUpperCase()}</span>
        <h3>${escapeHtml(post.title)}</h3>
        <p>${escapeHtml(post.summary)}</p>
        <div class="card-meta">
            <span>${escapeHtml(post.date)}</span>
            <span>${escapeHtml(post.difficulty)}</span>
            <span>${post.tags.map((tag) => `#${escapeHtml(tag)}`).join(' ')}</span>
        </div>
    </a>
`;

const renderWriteupList = () => {
    const grid = document.getElementById('writeupGrid');

    if (grid && siteData.posts) {
        grid.innerHTML = siteData.posts.map(postCard).join('');
    }

    const latest = document.getElementById('latestWriteups');

    if (latest && siteData.posts) {
        latest.innerHTML = siteData.posts.slice(0, 3).map(postCard).join('');
    }
};

const renderMembers = () => {
    const grid = document.getElementById('memberGrid');

    if (!grid || !siteData.members) {
        return;
    }

    grid.innerHTML = siteData.members.map((member) => `
        <article class="member-card">
            <header>
                <div class="avatar">${escapeHtml(member.id)}</div>
                <div>
                    <h3>${escapeHtml(member.name)}</h3>
                    <small>${escapeHtml(member.role)}</small>
                </div>
            </header>
            <p>${escapeHtml(member.bio)}</p>
            <div class="skill-list">
                ${member.skills.map((skill) => `<span>${escapeHtml(skill)}</span>`).join('')}
            </div>
        </article>
    `).join('');
};

const renderHonors = () => {
    const honorGrid = document.getElementById('honorGrid');
    const scoreboard = document.getElementById('scoreboard');
    const timeline = document.getElementById('timeline');

    if (honorGrid && siteData.honors) {
        honorGrid.innerHTML = siteData.honors.map((honor) => `
            <article class="honor-card">
                <small>${escapeHtml(honor.season)}</small>
                <strong>${escapeHtml(honor.rank)}</strong>
                <h3>${escapeHtml(honor.title)}</h3>
                <p>${escapeHtml(honor.description)}</p>
            </article>
        `).join('');
    }

    if (scoreboard && siteData.stats) {
        scoreboard.innerHTML = siteData.stats.map((item) => `
            <div>
                <strong>${escapeHtml(item.value)}</strong>
                <span>${escapeHtml(item.label)}</span>
            </div>
        `).join('');
    }

    if (timeline && siteData.timeline) {
        timeline.innerHTML = siteData.timeline.map((item) => `
            <li>
                <time>${escapeHtml(item.time)}</time>
                <div>
                    <h3>${escapeHtml(item.title)}</h3>
                    <p>${escapeHtml(item.description)}</p>
                </div>
            </li>
        `).join('');
    }
};

const setupWriteupFilters = () => {
    const filterButtons = document.querySelectorAll('[data-filter]');
    const writeupSearch = document.getElementById('writeupSearch');
    const emptyState = document.querySelector('.empty-state');
    let activeFilter = 'all';

    const applyFilters = () => {
        const cards = document.querySelectorAll('[data-card]');
        const keyword = (writeupSearch?.value || '').trim().toLowerCase();
        let visibleCount = 0;

        cards.forEach((card) => {
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

    applyFilters();
};

const inlineMarkdown = (text) => escapeHtml(text)
    .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1">')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>');

const markdownToHtml = (markdown) => {
    const lines = markdown.replace(/\r\n/g, '\n').split('\n');
    const html = [];
    let inCode = false;
    let codeLang = '';
    let codeBuffer = [];
    let inList = false;

    const closeList = () => {
        if (inList) {
            html.push('</ul>');
            inList = false;
        }
    };

    lines.forEach((line) => {
        const codeMatch = line.match(/^```(\w+)?/);

        if (codeMatch) {
            if (inCode) {
                html.push(`<pre><code class="language-${escapeHtml(codeLang)}">${escapeHtml(codeBuffer.join('\n'))}</code></pre>`);
                codeBuffer = [];
                codeLang = '';
                inCode = false;
            } else {
                closeList();
                inCode = true;
                codeLang = codeMatch[1] || '';
            }
            return;
        }

        if (inCode) {
            codeBuffer.push(line);
            return;
        }

        if (!line.trim()) {
            closeList();
            return;
        }

        const heading = line.match(/^(#{1,6})\s+(.+)$/);

        if (heading) {
            closeList();
            const level = heading[1].length;
            html.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
            return;
        }

        const listItem = line.match(/^[-*]\s+(.+)$/);

        if (listItem) {
            if (!inList) {
                html.push('<ul>');
                inList = true;
            }
            html.push(`<li>${inlineMarkdown(listItem[1])}</li>`);
            return;
        }

        const quote = line.match(/^>\s+(.+)$/);

        if (quote) {
            closeList();
            html.push(`<blockquote>${inlineMarkdown(quote[1])}</blockquote>`);
            return;
        }

        closeList();
        html.push(`<p>${inlineMarkdown(line)}</p>`);
    });

    closeList();

    if (inCode) {
        html.push(`<pre><code class="language-${escapeHtml(codeLang)}">${escapeHtml(codeBuffer.join('\n'))}</code></pre>`);
    }

    return html.join('\n');
};

const renderPost = async () => {
    const container = document.getElementById('postContent');

    if (!container || !siteData.posts) {
        return;
    }

    const params = new URLSearchParams(window.location.search);
    const slug = params.get('post') || siteData.posts[0]?.slug;
    const post = siteData.posts.find((item) => item.slug === slug);
    const postTitle = document.getElementById('postTitle');
    const postMeta = document.getElementById('postMeta');
    const postSlugLabel = document.getElementById('postSlugLabel');

    if (!post) {
        container.innerHTML = '<p class="muted">未找到这篇 Writeup，请返回列表重新选择。</p>';
        return;
    }

    if (postTitle) {
        postTitle.textContent = post.title;
        postTitle.dataset.text = post.title;
    }

    if (postMeta) {
        postMeta.innerHTML = `
            <span>${escapeHtml(post.date)}</span>
            <span>${escapeHtml(post.category).toUpperCase()}</span>
            <span>${escapeHtml(post.difficulty)}</span>
            <span>${post.tags.map((tag) => `#${escapeHtml(tag)}`).join(' ')}</span>
        `;
    }

    if (postSlugLabel) {
        postSlugLabel.textContent = post.slug;
    }

    document.title = `${post.title} | LZ-Team`;

    try {
        const response = await fetch(post.file);

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const markdown = await response.text();
        container.innerHTML = markdownToHtml(markdown);
    } catch (error) {
        container.innerHTML = `<p class="muted">Markdown 加载失败：${escapeHtml(error.message)}。请确认通过 HTTP 服务或 GitHub Pages 访问，而不是直接双击本地 HTML。</p>`;
    }
};

const setupTerminal = () => {
    const form = document.getElementById('terminalForm');
    const input = document.getElementById('terminalInput');
    const output = document.getElementById('terminalOutput');

    if (!form || !input || !output) {
        return;
    }

    const appendLine = (content, className = '') => {
        const line = document.createElement('p');
        line.className = className;
        line.innerHTML = content;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    };

    const responses = {
        help: 'available commands: help, cat /flag, whoami, id, pwd, ls, nc -lvnp 2026, date, clear',
        'cat /flag': '<span class="success">LZCTF{W3lc0m3_T0_LZ_2026!!!}</span>',
        whoami: 'lz-team',
        id: 'uid=2026(lz) gid=2026(ctf) groups=web,pwn,reverse,crypto,misc',
        pwd: '/home/lz-team',
        ls: 'posts&nbsp;&nbsp;assets&nbsp;&nbsp;writeups.html&nbsp;&nbsp;members.html&nbsp;&nbsp;honors.html&nbsp;&nbsp;flag',
        'nc -lvnp 2026': 'listening on [any] 2026 ... connect to [127.0.0.1] from challenger',
        date: new Date().toLocaleString()
    };

    form.addEventListener('submit', (event) => {
        event.preventDefault();

        const command = input.value.trim();

        if (!command) {
            return;
        }

        appendLine(`<span class="prompt">lz@team:~$</span> ${escapeHtml(command)}`);
        input.value = '';

        if (command === 'clear') {
            output.innerHTML = '';
            return;
        }

        appendLine(responses[command] || `command not found: ${escapeHtml(command)}. try <code>help</code>.`);
    });
};

renderWriteupList();
renderMembers();
renderHonors();
setupWriteupFilters();
renderPost();
setupTerminal();
