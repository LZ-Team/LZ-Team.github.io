export interface Project {
  title: string;
  description: string;
  href: string;
  tags: string[];
  icon: string;
  external?: boolean;
}

/**
 * 战队作品 / 开源项目。
 * 这是示例数据，替换为自己的作品即可，页面会自动渲染为链接卡片。
 */
export const projects: Project[] = [
  {
    title: 'dome',
    description: '',
    href: '',
    tags: [],
    icon: 'ph:bug',
    external: true,
  },
];
