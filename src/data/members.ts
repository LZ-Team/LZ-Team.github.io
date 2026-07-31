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
    skills: ['AI', '溯源取证']
  },
  {
    id: '0x02',
    name: 'ST4R',
    role: 'Misc / ALL',
    bio: '',
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
    skills: ['Reverse', 'AI']
  },
  {
    id: '0x05',
    name: 'suancaisoup',
    role: 'Pwn',
    bio: '',
    skills: ['Pwn']
  },
  {
    id: '0x06',
    name: 'miffya',
    role: 'Pwn',
    bio: '',
    skills: ['Pwn']
  },
  {
    id: '0x07',
    name: 't0rch',
    role: 'Reverse',
    bio: '',
    skills: ['Reverse']
  },
  {
    id: '0x08',
    name: 'warmlight',
    role: 'Reverse',
    bio: '',
    skills: ['Reverse']
  }

];
