export interface CreditEntry {
  name: string;
  license: string;
  role: string;
  note?: string;
  url?: string;
}

export const ABOUT_PRODUCT = {
  name: 'Antiwire',
  clientLabel: 'Desktop Client',
  version: '0.1.0',
  copyright: 'Copyright © 2026 Antiwire (zeromttr)',
  tagline: 'Open-source network monitor and firewall client for the Antiwire daemon.',
  description:
    'Built for highly secure environments. The desktop client runs with standard user privileges and talks to the elevated Antiwire service daemon over a pinned gRPC channel.',
  licenseName: 'MIT License',
} as const;

export const MIT_LICENSE_TEXT = `MIT License

Copyright (c) 2026 Antiwire (zeromttr)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

export const FRAMEWORK_CREDITS: CreditEntry[] = [
  {
    name: 'React',
    license: 'MIT',
    role: 'UI framework',
    url: 'https://react.dev',
    note: 'Copyright (c) Meta Platforms, Inc. and affiliates. See the React LICENSE for the full notice.',
  },
  {
    name: 'React Router',
    license: 'MIT',
    role: 'Application routing',
    url: 'https://reactrouter.com',
  },
  {
    name: 'Electron',
    license: 'MIT',
    role: 'Desktop shell and native bridge',
    url: 'https://www.electronjs.org',
  },
  {
    name: 'Vite',
    license: 'MIT',
    role: 'Frontend build tooling',
    url: 'https://vitejs.dev',
  },
  {
    name: 'Lucide Icons',
    license: 'ISC',
    role: 'Navigation and UI icons',
    url: 'https://lucide.dev',
  },
];

export const PACKAGE_CREDITS: CreditEntry[] = [
  {
    name: 'electron',
    license: 'MIT',
    role: 'Chromium and Node.js desktop runtime',
    url: 'https://www.npmjs.com/package/electron',
  },
  {
    name: 'react',
    license: 'MIT',
    role: 'Component model and rendering',
    url: 'https://www.npmjs.com/package/react',
  },
  {
    name: 'react-dom',
    license: 'MIT',
    role: 'DOM renderer for React',
    url: 'https://www.npmjs.com/package/react-dom',
  },
  {
    name: 'react-router',
    license: 'MIT',
    role: 'Client-side routing',
    url: 'https://www.npmjs.com/package/react-router',
  },
  {
    name: '@radix-ui/react-dialog',
    license: 'MIT',
    role: 'Accessible dialog primitives',
    url: 'https://www.npmjs.com/package/@radix-ui/react-dialog',
  },
  {
    name: '@radix-ui/react-alert-dialog',
    license: 'MIT',
    role: 'Accessible confirmation dialogs',
    url: 'https://www.npmjs.com/package/@radix-ui/react-alert-dialog',
  },
  {
    name: 'lucide-react',
    license: 'ISC',
    role: 'Icon components',
    url: 'https://www.npmjs.com/package/lucide-react',
  },
  {
    name: '@tanstack/react-virtual',
    license: 'MIT',
    role: 'Virtualized tables',
    url: 'https://www.npmjs.com/package/@tanstack/react-virtual',
  },
  {
    name: '@grpc/grpc-js',
    license: 'Apache-2.0',
    role: 'gRPC channel to the Antiwire daemon',
    url: 'https://www.npmjs.com/package/@grpc/grpc-js',
  },
  {
    name: '@grpc/proto-loader',
    license: 'Apache-2.0',
    role: 'Protocol buffer definitions for the daemon API',
    url: 'https://www.npmjs.com/package/@grpc/proto-loader',
  },
  {
    name: 'zod',
    license: 'MIT',
    role: 'Validation of data crossing the native bridge',
    url: 'https://www.npmjs.com/package/zod',
  },
  {
    name: 'clsx',
    license: 'MIT',
    role: 'Class name composition',
    url: 'https://www.npmjs.com/package/clsx',
  },
  {
    name: '@fontsource/ibm-plex-sans',
    license: 'OFL-1.1',
    role: 'Self-hosted sans-serif font assets',
    url: 'https://www.npmjs.com/package/@fontsource/ibm-plex-sans',
  },
  {
    name: '@fontsource/jetbrains-mono',
    license: 'OFL-1.1',
    role: 'Self-hosted monospace font assets',
    url: 'https://www.npmjs.com/package/@fontsource/jetbrains-mono',
  },
];

export const FONT_CREDITS: CreditEntry[] = [
  {
    name: 'IBM Plex Sans',
    license: 'SIL Open Font License 1.1',
    role: 'Primary sans-serif typeface (via @fontsource)',
    url: 'https://github.com/IBM/plex',
    note: 'Copyright © 2017 IBM Corp. with Reserved Font Name "Plex". This Font Software is licensed under the SIL Open Font License, Version 1.1. https://scripts.sil.org/OFL',
  },
  {
    name: 'JetBrains Mono',
    license: 'SIL Open Font License 1.1',
    role: 'Primary monospace typeface (via @fontsource)',
    url: 'https://github.com/JetBrains/JetBrainsMono',
    note: 'Copyright © The JetBrains Mono Project Authors. This Font Software is licensed under the SIL Open Font License, Version 1.1. https://scripts.sil.org/OFL',
  },
  {
    name: 'Cascadia Mono',
    license: 'SIL Open Font License 1.1',
    role: 'Preferred system monospace on Windows when installed',
    url: 'https://github.com/microsoft/cascadia-code',
  },
];

export const DATA_CREDITS: CreditEntry[] = [
  {
    name: 'DB-IP Lite',
    license: 'CC BY 4.0',
    role: 'GeoIP / ASN resolution data (daemon)',
    url: 'https://db-ip.com/db/lite.php',
    note: 'IP geolocation data used by the Antiwire daemon is intended to be derived from DB-IP Lite. Attribution is required under the Creative Commons Attribution 4.0 International license: https://creativecommons.org/licenses/by/4.0/ See the project NOTICE file for snapshot details.',
  },
  {
    name: 'HaGeZi DNS blocklists',
    license: 'GPL-3.0',
    role: 'Optional community hosts blocklists and abused TLD list',
    url: 'https://github.com/hagezi/dns-blocklists',
  },
  {
    name: 'URLhaus via malware-filter',
    license: 'CC0-1.0 / MIT',
    role: 'Optional malware hosts blocklist (URLhaus data by abuse.ch)',
    url: 'https://gitlab.com/malware-filter/urlhaus-filter',
    note: 'URLhaus data is published by abuse.ch under CC0. The malware-filter project removes popular domains from it and is not endorsed by abuse.ch.',
  },
  {
    name: 'Phishing Army',
    license: 'CC BY-NC 4.0',
    role: 'Optional phishing domains blocklist',
    url: 'https://phishing.army',
    note: 'Phishing Army blocklist by Andrea Draghetti, licensed under Creative Commons Attribution-NonCommercial 4.0 International: https://creativecommons.org/licenses/by-nc/4.0/ The list is downloaded by the user and is not redistributed with Antiwire.',
  },
  {
    name: 'StevenBlack hosts',
    license: 'MIT',
    role: 'Optional unified hosts blocklist',
    url: 'https://github.com/StevenBlack/hosts',
  },
  {
    name: '1Hosts',
    license: 'MPL-2.0',
    role: 'Optional community hosts blocklists',
    url: 'https://github.com/badmojr/1Hosts',
  },
  {
    name: 'someonewhocares.org hosts',
    license: 'Project terms apply',
    role: 'Optional hosts blocklist',
    url: 'https://someonewhocares.org/hosts/',
  },
];

export const RUNTIME_CREDITS: CreditEntry[] = [
  {
    name: 'Npcap',
    license: 'Npcap OEM / free license',
    role: 'Windows packet capture driver (optional runtime)',
    url: 'https://npcap.com',
    note: 'Npcap is required for packet-capture features on Windows and is installed separately by the user. Npcap is a product of Nmap Software LLC. Use is subject to the Npcap license: https://npcap.com/oem/redist.html',
  },
  {
    name: 'WinDivert',
    license: 'LGPL-3.0',
    role: 'Windows flow ownership and DNS packet diversion (runtime)',
    url: 'https://reqrypt.org/windivert.html',
    note: 'WinDivert 2.2 is used only when you turn it on in the settings. It is then loaded dynamically from the official package published by basil. It is not statically linked, and the driver and DLL are not vendored in this repository. Use is subject to the GNU Lesser General Public License v3: https://github.com/basil00/WinDivert/blob/master/LICENSE',
  },
  {
    name: 'libpcap',
    license: 'BSD-3-Clause',
    role: 'Packet capture on macOS / Linux (planned platforms)',
    url: 'https://www.tcpdump.org',
  },
];
