window.LZ_SITE_DATA = {
    posts: [
        {
            slug: 'jwt-key-confusion',
            title: 'JWT Key Confusion',
            category: 'web',
            difficulty: 'Hard',
            date: '2026-01-18',
            tags: ['jwt', 'source-audit', 'auth-bypass'],
            summary: '通过算法混淆与公钥复用完成身份伪造，进入 admin 面板后读取 /flag。',
            file: 'posts/jwt-key-confusion.md'
        },
        {
            slug: 'ret2libc-fast-path',
            title: 'ret2libc Fast Path',
            category: 'pwn',
            difficulty: 'Medium',
            date: '2026-02-06',
            tags: ['rop', 'libc', 'pwntools'],
            summary: '利用栈溢出泄露 puts 地址，计算 libc 基址并构造 system("/bin/sh")。',
            file: 'posts/ret2libc-fast-path.md'
        },
        {
            slug: 'rsa-common-modulus',
            title: 'RSA Common Modulus',
            category: 'crypto',
            difficulty: 'Easy',
            date: '2026-02-21',
            tags: ['rsa', 'egcd', 'number-theory'],
            summary: '同模不同指数场景下使用扩展欧几里得合并密文，恢复明文 flag。',
            file: 'posts/rsa-common-modulus.md'
        },
        {
            slug: 'vm-bytecode-crackme',
            title: 'VM Bytecode Crackme',
            category: 'reverse',
            difficulty: 'Hard',
            date: '2026-03-09',
            tags: ['vm', 'z3', 'ida'],
            summary: '还原虚拟机指令集，编写解释器逆推输入约束，自动求解正确 flag。',
            file: 'posts/vm-bytecode-crackme.md'
        },
        {
            slug: 'memory-forensics-trail',
            title: 'Memory Forensics Trail',
            category: 'misc',
            difficulty: 'Medium',
            date: '2026-03-27',
            tags: ['volatility', 'forensics', 'traffic'],
            summary: '从内存镜像中定位进程、提取网络连接与剪贴板痕迹，拼接最终线索。',
            file: 'posts/memory-forensics-trail.md'
        },
        {
            slug: 'ssti-sandbox-escape',
            title: 'SSTI Sandbox Escape',
            category: 'web',
            difficulty: 'Medium',
            date: '2026-04-12',
            tags: ['ssti', 'python', 'sandbox'],
            summary: '利用模板对象链绕过黑名单，执行命令并通过 cat /flag 完成读取。',
            file: 'posts/ssti-sandbox-escape.md'
        }
    ],
    members: [
        {
            id: '0x01',
            name: 'RootLZ',
            role: 'Captain / Web',
            bio: '偏爱源码审计、权限绕过和业务逻辑漏洞，口头禅是“先看路由，再找入口”。',
            skills: ['PHP', 'Node.js', 'SSTI', 'SQLi']
        },
        {
            id: '0x02',
            name: 'StackGhost',
            role: 'Pwn / Exploit',
            bio: '在 gdb 和 pwndbg 里生活，擅长 ROP、堆利用、格式化字符串和 libc 猜谜。',
            skills: ['ROP', 'Heap', 'Kernel', 'pwntools']
        },
        {
            id: '0x03',
            name: 'ByteNeko',
            role: 'Reverse / Mobile',
            bio: '喜欢把混淆拆成控制流，把 VM 还原成指令表，把输入约束交给自动化脚本。',
            skills: ['IDA', 'Frida', 'Android', 'Z3']
        },
        {
            id: '0x04',
            name: 'CryptoFox',
            role: 'Crypto / Math',
            bio: '专注 RSA、椭圆曲线、格攻击和伪随机分析，坚信数学才是最优雅的 payload。',
            skills: ['RSA', 'ECC', 'LLL', 'SageMath']
        },
        {
            id: '0x05',
            name: 'PacketKid',
            role: 'Misc / Forensics',
            bio: '抓包、取证、隐写、流量复原都能接，最常用的命令是 strings、binwalk 和 tshark。',
            skills: ['Wireshark', 'Volatility', 'Stego', 'OSINT']
        },
        {
            id: '0x06',
            name: 'ShellRunner',
            role: 'DevOps / Infra',
            bio: '维护训练平台、靶机环境和自动化脚本，让每一场比赛都稳定上线、快速复盘。',
            skills: ['Docker', 'Linux', 'CI/CD', 'Monitor']
        }
    ],
    honors: [
        {
            season: '2026 Spring',
            rank: 'Top 3',
            title: '高校网络安全挑战赛',
            description: 'Web 与 Crypto 双线突破，最后阶段依靠 Pwn 题完成反超。'
        },
        {
            season: '2026 Online',
            rank: '1st Blood',
            title: 'LZCTF Internal Cup',
            description: '开赛 17 分钟拿下首血，payload 记录已沉淀到训练库。'
        },
        {
            season: '2025 Winter',
            rank: 'Top 10',
            title: '全国大学生 CTF 联赛',
            description: '多方向稳定得分，团队协作流程和赛后复盘体系正式成型。'
        }
    ],
    timeline: [
        {
            time: '2026-04',
            title: '完成战队知识库重构',
            description: '统一题目标签、难度、复盘模板和 payload 归档方式。'
        },
        {
            time: '2026-02',
            title: '建立二进制专项训练',
            description: '围绕 ROP、堆利用、沙箱逃逸建立持续训练计划。'
        },
        {
            time: '2025-11',
            title: '首次进入全国赛 Top 10',
            description: '多方向均衡得分，战队协同体系进入稳定阶段。'
        }
    ],
    stats: [
        { value: '32', label: '参赛场次' },
        { value: '18', label: '获奖记录' },
        { value: '126', label: 'Writeups' },
        { value: '9', label: 'First Blood' }
    ]
};
