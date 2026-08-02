// @ts-check
import { defineConfig } from 'astro/config';
import { unified } from '@astrojs/markdown-remark';
import remarkNormalizeLang from './remark-normalize-lang.mjs';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';
import icon from 'astro-icon';

// https://astro.build/config
export default defineConfig({
  // LZ-Team.github.io 为 User/Org Pages，站点部署在根路径，无需 base
  site: 'https://LZ-Team.github.io',
  output: 'static',
  build: {
    // 保持与 GitHub Pages 兼容的输出格式
    format: 'directory'
  },
  integrations: [
    // Iconify 图标（Phosphor 线性集），构建时内联 SVG、仅打包用到的图标
    icon({
      include: {
        ph: [
          'arrow-up',
          'arrow-up-right',
          'arrow-right',
          'arrow-down',
          'magnifying-glass',
          'house',
          'users-three',
          'trophy',
          'notebook',
          'squares-four',
          'globe',
          'bug',
          'binary',
          'key',
          'question',
          'flag',
          'file-x',
          'link',
          'link-break'
        ]
      }
    })
  ],
  markdown: {
    // Astro 7：使用 @astrojs/markdown-remark 的 unified 处理器配置插件
    processor: unified({
      remarkPlugins: [remarkNormalizeLang, remarkMath],
      // KaTeX 数学公式（$...$ 行内 / $$...$$ 独立公式）
      // throwOnError: false —— 公式语法瑕疵红字显示原文，不拖垮构建
      // strict: false —— 消除 Unicode/中文混入数学导致的控制台警告刷屏
      rehypePlugins: [[rehypeKatex, { throwOnError: false, errorColor: '#f87171', strict: false }]]
    }),
    // Shiki 语法高亮，深色优先
    shikiConfig: {
      theme: 'github-dark',
      wrap: true
    }
  }
});
