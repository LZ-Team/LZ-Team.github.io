# LZ-Team · CTF Cyber Base

## 🗂 目录结构

```
├── public/                  # 静态资源（logo、.nojekyll）
├── src/
│   ├── components/          # Sidebar、Footer、PostCard 等组件
│   ├── content/             # 文章 Markdown ！！
│   ├── content.config.ts    # 文章 front-matter 类型与校验
│   ├── data/                # 成员、荣誉、项目  ！！
│   ├── layouts/             # Base 布局（含主题注入、页面切换过渡、背景层）
│   ├── pages/               # 页面路由（Home/Members/Honors/Blog/Projects）
│   ├── scripts/             # 客户端脚本（主题、矩阵、滚动进度、筛选、复制等）
│   └── styles/              # 全局设计系统
├── .github/workflows/       # GitHub Pages 自动部署
└── astro.config.mjs         # Astro 配置
```

## 🗺 页面

| 路由 | 说明 |
| --- | --- |
| `/` | 主页 |
| `/blog` | 博客页 |
| `/members` | 成员介绍 |
| `/honors` | 荣誉时间线 |
| `/projects` | 项目页 |
| `/posts/[slug]` | 文章详情 |

## 🚀 本地开发

```bash
# 安装依赖
npm install

# 启动开发服务器（带热更新）
npm run dev

# 类型检查
npm run check

# 构建生产产物（输出到 dist/）
npm run build

# 本地预览构建产物
npm run preview
```

## ✍️ 发布新 Writeup

1. 在 `src/content/` 下新建 `.md` 文件，例如 `mychallenge.md`
2. 编写 front-matter（字段校验见 `src/content.config.ts`）：

   ```yaml
   ---
   title: My Challenge Writeup
   description: 一句话摘要，会展示在卡片与列表页
   date: 2026-08-01
   categories:
     - Web
     - CTF-Writeup
   tags:
     - XSS
     - CSP
   difficulty: Medium
   index_img: https://example.com/cover.png
   banner_img: https://example.com/cover.png
   ---
   ```

3. 正文用标准 Markdown 编写，代码块写清语言（如 ` ```python `）即可自动高亮
4. 保存后 `npm run dev` 即可实时预览；提交后由 GitHub Actions 自动部署

> 提示：`categories` 首项作为主要分类（用于列表筛选）。标题、难度、封面不填时均有默认值。

## 👥 更新成员 / 项目 / 荣誉

直接编辑 `src/data/` 下的类型化模块即可，页面会在构建时自动渲染。

- `members.ts`：成员
- `projects.ts`：项目链接卡片
- `honors.ts`：荣誉与统计

## ☁️ 部署（GitHub Pages）

仓库已配置 `.github/workflows/deploy.yml`：

1. 确认 `astro.config.mjs` 中 `site` 与你的仓库名一致（User/Org Pages 部署在根路径无需 `base`）
2. 推送 `main` 分支，Actions 会自动执行 `npm ci && npm run build` 并把 `dist/` 发布到 Pages
3. 首次部署需在仓库 **Settings → Pages** 中把 Source 设为 **GitHub Actions**

## 🧩 常用脚本

| 命令 | 说明 |
| --- | --- |
| `npm run dev` | 本地开发 |
| `npm run build` | 生产构建 |
| `npm run preview` | 预览产物 |
| `npm run check` | 类型检查 |
