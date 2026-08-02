export interface Member {
  id: string;
  name: string;
  role: string;
  bio: string;
  skills: string[];
  avatar?: string;
  blog?: string;
}

export const members: Member[] = [
  {
    id: '0x01',
    name: 'XU17',
    role: 'Captain / Web',
    bio: '',
    avatar: 'https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202412222328446.jpg',
    blog: 'https://xu17.top/',
    skills: ['Web', 'AI']
  },
  {
    id: '0x02',
    name: 'ST4R',
    role: 'Misc / ALL',
    bio: '',
    avatar: 'https://nanxer-1322358327.cos.ap-guangzhou.myqcloud.com/blog/st4r.jpg',
    blog: '',
    skills: ['AI', '溯源取证']
  },
  {
    id: '0x03',
    name: 'Nanxer',
    role: 'Crypto',
    avatar: 'https://nanxer-1322358327.cos.ap-guangzhou.myqcloud.com/blog/header.png',
    blog: 'https://nanxer.it4keth2ee.top/',
    bio: '',
    skills: ['Crypto', '溯源取证', '格', 'ECC']
  },
  {
    id: '0x04',
    name: 'DreamCat',
    role: 'Reverse',
    bio: '',
    avatar: 'https://nanxer-1322358327.cos.ap-guangzhou.myqcloud.com/blog/dreamCat.jpg',
    blog: '',
    skills: ['Reverse', 'AI']
  },
  {
    id: '0x05',
    name: 'suancaisoup',
    role: 'Pwn',
    bio: '',
    avatar: 'https://nanxer-1322358327.cos.ap-guangzhou.myqcloud.com/blog/202603042216448157118.jpg',
    blog: '',
    skills: ['Pwn']
  },
  {
    id: '0x06',
    name: 'miffya',
    role: 'Pwn',
    bio: '',
    avatar: 'https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202412241939695.jpg',
    blog: 'https://www.cnblogs.com/miffya',
    skills: ['Pwn']
  },
  {
    id: '0x07',
    name: 't0rch',
    role: 'Reverse',
    bio: '',
    avatar: 'https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202501112240758.jpg',
    blog: 'https://bbs.kanxue.com/homepage-1019613.htm',
    skills: ['Reverse']
  },
  {
    id: '0x08',
    name: 'warmlight',
    role: 'Reverse',
    bio: '',
    avatar: 'https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202412241937379.jpeg',
    blog: 'https://warmlight19.github.io/',
    skills: ['Reverse']
  }

];
