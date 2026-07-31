/**
 * remark 插件：规范化代码块语言标签。
 * 旧文章里大量使用 `Python`/`HTTP`/`Plain` 等大小写标签，
 * Shiki 的语言名是区分大小写的，这里统一转小写并映射别名，避免逐个修改文章。
 */
const ALIASES = {
  plain: 'plaintext',
  properties: 'ini',
  shell: 'bash',
  sh: 'bash',
  js: 'javascript',
  ts: 'typescript',
  py: 'python',
  cpp: 'cpp',
  html: 'html',
  visual: 'plaintext'
};

function walk(node) {
  if (!node || typeof node !== 'object') return;

  if (node.type === 'code' && node.lang) {
    const lower = String(node.lang).toLowerCase();
    node.lang = ALIASES[lower] || lower;
  }

  for (const key of Object.keys(node)) {
    if (key === 'position' || key === 'data') continue;
    const value = node[key];
    if (Array.isArray(value)) {
      value.forEach(walk);
    } else if (value && typeof value === 'object') {
      walk(value);
    }
  }
}

export default function remarkNormalizeLang() {
  return (tree) => {
    walk(tree);
  };
}
