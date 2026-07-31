import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

/**
 * 文章内容集合。
 * 文章直接存放在 src/content/ 根目录下（.md），front-matter 经过类型校验。
 */
const posts = defineCollection({
  loader: glob({ pattern: '*.md', base: './src/content' }),
  schema: z.object({
    title: z.string(),
    description: z.string().default(''),
    date: z.coerce.date(),
    updated: z.coerce.date().optional(),
    // 支持多个分类
    categories: z.array(z.string()).default(['Misc']),
    tags: z.array(z.string()).default([]),
    difficulty: z.enum(['Easy', 'Normal', 'Medium', 'Hard', 'Insane']).default('Normal'),
    author: z.string().default('LZ-Team'),
    draft: z.boolean().default(false),
    index_img: z.string().url().optional(),
    banner_img: z.string().url().optional()
  })
});

export const collections = { posts };
