import { describe, expect, it } from 'bun:test';
import {
  IconThemes,
  LinuxAppIcons,
  dataDirs,
  execWords,
  matchDesktopEntry,
  parseKeyFile,
  parseSettingString,
  parseTheme,
  readDesktopEntries,
  userIconThemes,
  type DesktopEntry,
  type IconFs,
} from './linux-icons';

/**
 * A file system in memory. `files` maps a path to its text; `links` maps a path to what it
 * points at. Directories are whatever the files imply.
 */
function fakeFs(files: Record<string, string>, links: Record<string, string> = {}) {
  const reads: string[] = [];
  const resolve = (file: string): string | null => {
    let current = file;
    for (let hops = 0; hops < 8 && links[current] !== undefined; hops++) current = links[current];
    return current in files ? current : null;
  };
  const isDirectory = (dir: string) => Object.keys(files).some((f) => f.startsWith(`${dir}/`));
  const fs: IconFs = {
    list: async (dir) => [
      ...new Set(
        Object.keys(files)
          .filter((f) => f.startsWith(`${dir}/`))
          .map((f) => f.slice(dir.length + 1).split('/')[0]),
      ),
    ],
    read: async (file) => {
      reads.push(file);
      return files[file] ?? null;
    },
    isFile: async (file) => file in files,
    isDirectory: async (dir) => isDirectory(dir),
    realpath: async (file) => resolve(file),
  };
  return { fs, reads };
}

function desktop(fields: Record<string, string>): string {
  const all = { Type: 'Application', ...fields };
  return ['[Desktop Entry]', ...Object.entries(all).map(([k, v]) => `${k}=${v}`), ''].join('\n');
}

const HICOLOR = `[Icon Theme]
Name=Hicolor
Directories=16x16/apps,32x32/apps,48x48/apps,48x48/mimetypes,48x48@2/apps,128x128/apps,256x256/apps,scalable/apps

[16x16/apps]
Size=16
Context=Applications
Type=Threshold

[32x32/apps]
Size=32
Context=Applications
Type=Threshold

[48x48/apps]
Size=48
Context=Applications
Type=Threshold

[48x48/mimetypes]
Size=48
Context=MimeTypes
Type=Threshold

[48x48@2/apps]
Size=48
Scale=2
Context=Applications
Type=Threshold

[128x128/apps]
Size=128
Context=Applications
Type=Threshold

[256x256/apps]
Size=256
Context=Applications
Type=Threshold

[scalable/apps]
MinSize=1
Size=128
MaxSize=256
Context=Applications
Type=Scalable
`;

const SEARCH = ['/usr/local/bin', '/usr/bin'];

describe('parseKeyFile', () => {
  it('reads groups and keys, skipping comments and anything before the first group', () => {
    const groups = parseKeyFile('stray=1\n# comment\n[A]\n k = v \n\n[B]\nk=w=x\n[A]\nk=later\n');
    expect(groups.get('A')?.get('k')).toBe('v');
    expect(groups.get('B')?.get('k')).toBe('w=x');
    expect([...groups.keys()]).toEqual(['A', 'B']);
  });
});

describe('execWords', () => {
  it('splits on spaces and honours quoted arguments', () => {
    expect(execWords('vim %F')).toEqual(['vim', '%F']);
    expect(execWords('"/opt/My App/app" --flag "a \\"b\\"" %U')).toEqual([
      '/opt/My App/app',
      '--flag',
      'a "b"',
      '%U',
    ]);
    expect(execWords('  ')).toEqual([]);
  });
});

describe('dataDirs', () => {
  it('puts the user data directory first and always includes the system and export ones', () => {
    expect(dataDirs({}, '/home/me')).toEqual([
      '/home/me/.local/share',
      '/usr/local/share',
      '/usr/share',
      '/home/me/.local/share/flatpak/exports/share',
      '/var/lib/flatpak/exports/share',
      '/var/lib/snapd/desktop',
    ]);
    const custom = dataDirs(
      { XDG_DATA_HOME: '/data/me', XDG_DATA_DIRS: '/nix/share/:relative:/usr/share' },
      '/home/me',
    );
    expect(custom.slice(0, 3)).toEqual(['/data/me', '/nix/share', '/usr/share']);
    expect(custom).toContain('/usr/local/share');
  });
});

describe('readDesktopEntries', () => {
  it('reads what starts each application and what its icon is', async () => {
    const { fs } = fakeFs(
      {
        '/usr/share/applications/vim.desktop': desktop({ Exec: 'vim %F', Icon: 'gvim' }),
        '/usr/share/applications/byobu.desktop': desktop({
          Exec: 'env TERM=xterm-256color byobu',
          Icon: 'byobu',
        }),
        '/usr/share/applications/kde/kate.desktop': desktop({
          Exec: '/usr/bin/kate -b %U',
          Icon: 'kate',
        }),
        '/usr/bin/vim.basic': '',
        '/usr/bin/byobu': '',
        '/usr/bin/kate': '',
      },
      { '/usr/bin/vim': '/etc/alternatives/vim', '/etc/alternatives/vim': '/usr/bin/vim.basic' },
    );
    const entries = await readDesktopEntries(fs, ['/usr/share'], SEARCH);
    expect(entries).toEqual([
      { id: 'byobu', program: 'byobu', target: '/usr/bin/byobu', args: 0, icon: 'byobu' },
      { id: 'kde-kate', program: '/usr/bin/kate', target: '/usr/bin/kate', args: 1, icon: 'kate' },
      { id: 'vim', program: 'vim', target: '/usr/bin/vim.basic', args: 0, icon: 'gvim' },
    ]);
  });

  it('lets an earlier directory override a later one, and a hidden entry delete it', async () => {
    const { fs } = fakeFs({
      '/home/me/.local/share/applications/a.desktop': desktop({ Exec: 'a', Icon: 'mine' }),
      '/home/me/.local/share/applications/b.desktop': desktop({
        Exec: 'b',
        Icon: 'b',
        Hidden: 'true',
      }),
      '/usr/share/applications/a.desktop': desktop({ Exec: 'a', Icon: 'theirs' }),
      '/usr/share/applications/b.desktop': desktop({ Exec: 'b', Icon: 'b' }),
    });
    const entries = await readDesktopEntries(fs, ['/home/me/.local/share', '/usr/share'], SEARCH);
    expect(entries.map((entry) => [entry.id, entry.icon])).toEqual([['a', 'mine']]);
  });

  it('leaves out links, entries without an icon and files that are not desktop entries', async () => {
    const { fs } = fakeFs({
      '/usr/share/applications/link.desktop': desktop({ Type: 'Link', Icon: 'x' }),
      '/usr/share/applications/bare.desktop': desktop({ Exec: 'bare' }),
      '/usr/share/applications/mimeinfo.cache': '[MIME Cache]\n',
      '/usr/share/applications/junk.desktop': 'not a desktop entry',
    });
    expect(await readDesktopEntries(fs, ['/usr/share'], SEARCH)).toEqual([]);
  });
});

function entry(id: string, program: string, target: string | null, icon = id, args = 0) {
  return { id, program, target, args, icon } satisfies DesktopEntry;
}

describe('matchDesktopEntry', () => {
  const entries = [
    entry('firefox', 'firefox', '/usr/lib/firefox/firefox.sh'),
    entry('google-chrome', '/usr/bin/google-chrome-stable', '/opt/google/chrome/google-chrome'),
    entry('org.gnome.Nautilus', 'nautilus', '/usr/bin/nautilus'),
    entry('com.discordapp.Discord', '/usr/bin/flatpak', '/usr/bin/flatpak', 'discord', 4),
    entry('org.videolan.VLC', '/usr/bin/flatpak', '/usr/bin/flatpak', 'vlc', 4),
    entry('libreoffice-writer', 'libreoffice', '/usr/lib/libreoffice/program/soffice', 'lo-w', 1),
    entry('libreoffice-startcenter', 'libreoffice', '/usr/lib/libreoffice/program/soffice', 'lo'),
    entry('libreoffice-calc', 'libreoffice', '/usr/lib/libreoffice/program/soffice', 'lo-c', 1),
    entry('firefox_firefox', '/snap/bin/firefox', '/usr/bin/snap', '/snap/firefox/1/icon.png'),
    entry('code_code', '/snap/bin/code', '/usr/bin/snap', '/snap/code/2/code.png'),
    entry('code_code-url-handler', '/snap/bin/code', '/usr/bin/snap', '/snap/code/2/code.png', 1),
  ];
  const iconOf = (exe: string) => matchDesktopEntry(entries, exe)?.icon ?? null;

  it('matches the program an entry starts', () => {
    expect(iconOf('/usr/bin/nautilus')).toBe('org.gnome.Nautilus');
    expect(iconOf('/opt/google/chrome/google-chrome')).toBe('google-chrome');
  });

  it('matches the binary a launcher script runs, by name or by sitting beside it', () => {
    expect(iconOf('/usr/lib/firefox/firefox')).toBe('firefox');
    expect(iconOf('/usr/lib/firefox/firefox-bin')).toBe('firefox');
    expect(iconOf('/opt/google/chrome/chrome')).toBe('google-chrome');
    expect(iconOf('/opt/google/chrome/chrome_crashpad_handler')).toBe('google-chrome');
  });

  it('matches an application inside a sandbox by the name in its desktop file ID', () => {
    expect(iconOf('/app/discord/Discord')).toBe('discord');
    expect(iconOf('/app/bin/vlc')).toBe('vlc');
  });

  it('prefers the plain launcher over an application mode', () => {
    expect(iconOf('/usr/lib/libreoffice/program/soffice.bin')).toBe('lo');
    expect(iconOf('/usr/lib/libreoffice/program/soffice')).toBe('lo');
  });

  it('matches a Snap by the name in its path', () => {
    expect(iconOf('/snap/firefox/4793/usr/lib/firefox/firefox')).toBe('/snap/firefox/1/icon.png');
    expect(iconOf('/snap/code/190/usr/share/code/code')).toBe('/snap/code/2/code.png');
  });

  it('does not take a launcher, or a neighbour in a shared directory, for an application', () => {
    // `flatpak` starts two applications here and is neither of them.
    expect(iconOf('/usr/bin/flatpak')).toBeNull();
    expect(iconOf('/usr/bin/snap')).toBeNull();
    // In `/usr/bin` with nautilus, and nothing to do with it.
    expect(iconOf('/usr/bin/curl')).toBeNull();
    expect(iconOf('/usr/lib/systemd/systemd-resolved')).toBeNull();
    expect(iconOf('/snap/unknown/1/bin/tool')).toBeNull();
  });
});

describe('parseTheme', () => {
  it('orders directories by how well their size fits, leaving out other display scales', () => {
    const theme = parseTheme(HICOLOR);
    expect(theme.dirs).toEqual([
      '48x48/apps',
      '48x48/mimetypes',
      'scalable/apps',
      '128x128/apps',
      '256x256/apps',
      '32x32/apps',
      '16x16/apps',
    ]);
    expect(theme.inherits).toEqual([]);
  });

  it('reads what a theme inherits from and refuses directories outside it', () => {
    const theme = parseTheme(
      '[Icon Theme]\nInherits=Adwaita, hicolor\nDirectories=../evil,/abs,apps/48\n' +
        '[../evil]\nSize=48\nContext=Applications\n[/abs]\nSize=48\nContext=Applications\n' +
        '[apps/48]\nSize=48\nContext=Applications\n',
    );
    expect(theme.dirs).toEqual(['apps/48']);
    expect(theme.inherits).toEqual(['Adwaita', 'hicolor']);
  });
});

describe('IconThemes', () => {
  const tree = {
    '/usr/share/icons/hicolor/index.theme': HICOLOR,
    '/usr/share/icons/hicolor/128x128/apps/antiwire.png': '',
    '/usr/share/icons/hicolor/scalable/apps/Alacritty.svg': '',
    '/usr/share/icons/hicolor/scalable/apps/gvim.svg': '',
    '/usr/share/icons/hicolor/48x48/apps/gvim.png': '',
    '/usr/share/icons/hicolor/16x16/apps/gvim.png': '',
    '/usr/share/icons/hicolor/48x48/mimetypes/text-plain.png': '',
    '/usr/share/icons/Papirus/index.theme':
      '[Icon Theme]\nInherits=breeze\nDirectories=48x48/apps\n[48x48/apps]\nSize=48\nContext=Applications\n',
    '/usr/share/icons/Papirus/48x48/apps/gvim.svg': '',
    '/usr/share/icons/breeze/index.theme':
      '[Icon Theme]\nInherits=Papirus,hicolor\nDirectories=apps/48\n[apps/48]\nSize=48\nContext=Applications\nType=Scalable\nMinSize=16\nMaxSize=256\n',
    '/usr/share/icons/breeze/apps/48/konsole.svg': '',
    '/home/me/.local/share/icons/hicolor/256x256/apps/mine.png': '',
    '/usr/share/pixmaps/legacy.png': '',
    '/usr/share/pixmaps/python3.xpm': '',
    '/opt/tool/icon.png': '',
    '/opt/tool/icon.xpm': '',
  };
  const themes = (preferred: string[] = []) =>
    new IconThemes(fakeFs(tree).fs, ['/home/me/.local/share', '/usr/share'], '/home/me', preferred);

  it('takes the size closest to what is drawn, from hicolor', async () => {
    expect(await themes().find('gvim')).toBe('/usr/share/icons/hicolor/48x48/apps/gvim.png');
    expect(await themes().find('Alacritty')).toBe(
      '/usr/share/icons/hicolor/scalable/apps/Alacritty.svg',
    );
    expect(await themes().find('antiwire')).toBe(
      '/usr/share/icons/hicolor/128x128/apps/antiwire.png',
    );
  });

  it('finds an icon the user installed, and one that is only in pixmaps', async () => {
    expect(await themes().find('mine')).toBe(
      '/home/me/.local/share/icons/hicolor/256x256/apps/mine.png',
    );
    expect(await themes().find('legacy')).toBe('/usr/share/pixmaps/legacy.png');
    expect(await themes().find('legacy.png')).toBe('/usr/share/pixmaps/legacy.png');
  });

  it("looks in the user's theme and what it inherits before hicolor", async () => {
    expect(await themes(['Papirus']).find('gvim')).toBe(
      '/usr/share/icons/Papirus/48x48/apps/gvim.svg',
    );
    // From breeze, which Papirus inherits; the loop between the two ends.
    expect(await themes(['Papirus']).find('konsole')).toBe(
      '/usr/share/icons/breeze/apps/48/konsole.svg',
    );
    expect(await themes(['Papirus']).find('antiwire')).toBe(
      '/usr/share/icons/hicolor/128x128/apps/antiwire.png',
    );
    expect(await themes().find('konsole')).toBeNull();
  });

  it('uses an absolute path as it is, when it is a picture the app can show', async () => {
    expect(await themes().find('/opt/tool/icon.png')).toBe('/opt/tool/icon.png');
    expect(await themes().find('/opt/tool/icon.xpm')).toBeNull();
    expect(await themes().find('/opt/tool/missing.png')).toBeNull();
  });

  it('finds a stock icon an entry names, whatever context the theme files it under', async () => {
    expect(await themes().find('text-plain')).toBe(
      '/usr/share/icons/hicolor/48x48/mimetypes/text-plain.png',
    );
  });

  it('finds nothing for a name with no usable file, or one that is not a name', async () => {
    expect(await themes().find('python3')).toBeNull();
    expect(await themes().find('nothing-here')).toBeNull();
    expect(await themes().find('../../etc/passwd')).toBeNull();
    expect(await themes().find('')).toBeNull();
  });

  it('still searches hicolor when it has no index.theme', async () => {
    const { fs } = fakeFs({ '/usr/share/icons/hicolor/64x64/apps/tool.png': '' });
    expect(await new IconThemes(fs, ['/usr/share'], '/home/me', []).find('tool')).toBe(
      '/usr/share/icons/hicolor/64x64/apps/tool.png',
    );
  });
});

const noSetting = async () => null;

describe('parseSettingString', () => {
  it('reads the string gsettings prints', () => {
    expect(parseSettingString("'Yaru'\n")).toBe('Yaru');
    expect(parseSettingString("'it\\'s'")).toBe("it's");
    expect(parseSettingString('')).toBeNull();
    expect(parseSettingString('No such schema')).toBeNull();
  });
});

describe('userIconThemes', () => {
  it('asks GSettings on GNOME and the desktops built on it', async () => {
    const asked: string[] = [];
    const setting = async (schema: string, key: string) => {
      asked.push(`${schema} ${key}`);
      return 'Yaru';
    };
    const { fs } = fakeFs({
      '/home/me/.config/gtk-3.0/settings.ini': '[Settings]\ngtk-icon-theme-name=Adwaita\n',
    });
    for (const desktop of ['GNOME', 'ubuntu:GNOME', 'Budgie:GNOME', 'Unity', 'Pantheon']) {
      expect([
        desktop,
        await userIconThemes(fs, { XDG_CURRENT_DESKTOP: desktop }, '/home/me', setting),
      ]).toEqual([desktop, ['Yaru', 'Adwaita']]);
    }
    expect(new Set(asked)).toEqual(new Set(['org.gnome.desktop.interface icon-theme']));

    asked.length = 0;
    await userIconThemes(fs, { XDG_CURRENT_DESKTOP: 'X-Cinnamon' }, '/home/me', setting);
    expect(asked).toEqual(['org.cinnamon.desktop.interface icon-theme']);
  });

  it('falls back to the GTK settings file when GSettings has no answer', async () => {
    const { fs } = fakeFs({
      '/home/me/.config/gtk-4.0/settings.ini': '[Settings]\ngtk-icon-theme-name=Papirus\n',
    });
    expect(
      await userIconThemes(fs, { XDG_CURRENT_DESKTOP: 'GNOME' }, '/home/me', noSetting),
    ).toEqual(['Papirus']);
  });

  it('reads kdeglobals on Plasma: the user file, then the defaults, then breeze', async () => {
    const kde = { XDG_CURRENT_DESKTOP: 'KDE' };
    const never = async () => {
      throw new Error('GSettings is not asked on Plasma');
    };
    const defaults = { '/home/me/.config/kdedefaults/kdeglobals': '[Icons]\nTheme=breeze-dark\n' };
    const chosen = { '/home/me/.config/kdeglobals': '[KDE]\nx=1\n[Icons]\nTheme=Papirus\n' };

    expect(
      await userIconThemes(fakeFs({ ...defaults, ...chosen }).fs, kde, '/home/me', never),
    ).toEqual(['Papirus']);
    expect(await userIconThemes(fakeFs(defaults).fs, kde, '/home/me', never)).toEqual([
      'breeze-dark',
    ]);
    expect(
      await userIconThemes(
        fakeFs({ '/etc/xdg/kdeglobals': '[Icons]\nTheme=oxygen\n' }).fs,
        kde,
        '/home/me',
        never,
      ),
    ).toEqual(['oxygen']);
    expect(await userIconThemes(fakeFs({}).fs, kde, '/home/me', never)).toEqual(['breeze']);
  });

  it('asks nothing on a desktop it does not know, and reads no stale Plasma file', async () => {
    const { fs } = fakeFs({
      '/home/me/.config/kdeglobals': '[Icons]\nTheme=breeze\n',
      '/home/me/.config/gtk-3.0/settings.ini': '[Settings]\ngtk-icon-theme-name=elementary\n',
    });
    const never = async () => {
      throw new Error('not asked');
    };
    expect(await userIconThemes(fs, { XDG_CURRENT_DESKTOP: 'XFCE' }, '/home/me', never)).toEqual([
      'elementary',
    ]);
    expect(await userIconThemes(fakeFs({}).fs, {}, '/home/me', never)).toEqual([]);
  });

  it('ignores a value that is not a theme name', async () => {
    const { fs } = fakeFs({
      '/cfg/gtk-3.0/settings.ini': '[Settings]\ngtk-icon-theme-name=../../etc\n',
    });
    const env = { XDG_CONFIG_HOME: '/cfg', XDG_CURRENT_DESKTOP: 'GNOME' };
    expect(await userIconThemes(fs, env, '/home/me', async () => '../evil')).toEqual([]);
  });
});

describe('LinuxAppIcons', () => {
  const tree = {
    '/usr/share/applications/Alacritty.desktop': desktop({ Exec: 'alacritty', Icon: 'Alacritty' }),
    '/usr/share/applications/antiwire.desktop': desktop({
      Exec: '/usr/bin/antiwire',
      Icon: 'antiwire',
    }),
    '/usr/share/applications/python3.desktop': desktop({
      Exec: '/usr/bin/python3',
      Icon: '/usr/share/pixmaps/python3.xpm',
    }),
    '/usr/bin/alacritty': '',
    '/usr/bin/python3': '',
    '/usr/lib/antiwire/antiwire': '',
    '/usr/share/pixmaps/python3.xpm': '',
    '/usr/share/icons/hicolor/index.theme': HICOLOR,
    '/usr/share/icons/hicolor/128x128/apps/antiwire.png': '',
    '/usr/share/icons/hicolor/scalable/apps/Alacritty.svg': '',
  };
  const links = { '/usr/bin/antiwire': '/usr/lib/antiwire/antiwire' };

  it("draws with the user's theme, where the desktop says which it is", async () => {
    const themed = {
      ...tree,
      '/usr/share/applications/info.desktop': desktop({ Exec: 'info', Icon: 'dialog-information' }),
      '/usr/bin/info': '',
      '/usr/share/icons/Yaru/index.theme':
        '[Icon Theme]\nInherits=hicolor\nDirectories=48x48/apps,48x48/status\n' +
        '[48x48/apps]\nSize=48\nContext=Applications\n[48x48/status]\nSize=48\nContext=Status\n',
      '/usr/share/icons/Yaru/48x48/apps/Alacritty.png': '',
      '/usr/share/icons/Yaru/48x48/status/dialog-information.png': '',
    };
    const env = { PATH: '/usr/bin', XDG_CURRENT_DESKTOP: 'ubuntu:GNOME' };
    const icons = new LinuxAppIcons(fakeFs(themed, links).fs, env, '/home/me', async () => 'Yaru');
    // The theme restyles this application, and has the stock icon another one names.
    expect(await icons.iconFile('/usr/bin/alacritty')).toBe(
      '/usr/share/icons/Yaru/48x48/apps/Alacritty.png',
    );
    expect(await icons.iconFile('/usr/bin/info')).toBe(
      '/usr/share/icons/Yaru/48x48/status/dialog-information.png',
    );
    // What the theme lacks still comes from hicolor.
    expect(await icons.iconFile('/usr/lib/antiwire/antiwire')).toBe(
      '/usr/share/icons/hicolor/128x128/apps/antiwire.png',
    );
  });

  it('goes from an executable to the icon file of its application', async () => {
    const icons = new LinuxAppIcons(
      fakeFs(tree, links).fs,
      { PATH: '/usr/bin' },
      '/home/me',
      noSetting,
    );
    expect(await icons.iconFile('/usr/bin/alacritty')).toBe(
      '/usr/share/icons/hicolor/scalable/apps/Alacritty.svg',
    );
    expect(await icons.iconFile('/usr/lib/antiwire/antiwire')).toBe(
      '/usr/share/icons/hicolor/128x128/apps/antiwire.png',
    );
    // An application whose only icon is an XPM, and a program that is no application.
    expect(await icons.iconFile('/usr/bin/python3')).toBeNull();
    expect(await icons.iconFile('/usr/bin/curl')).toBeNull();
  });

  it('reads the desktop entries once for many lookups, and again after a minute', async () => {
    let now = 0;
    const { fs, reads } = fakeFs(tree, links);
    const icons = new LinuxAppIcons(fs, { PATH: '/usr/bin' }, '/home/me', noSetting, () => now);
    const entryReads = () => reads.filter((file) => file.endsWith('antiwire.desktop')).length;

    await Promise.all([
      icons.iconFile('/usr/bin/alacritty'),
      icons.iconFile('/usr/lib/antiwire/antiwire'),
      icons.iconFile('/usr/bin/curl'),
    ]);
    await icons.iconFile('/usr/bin/alacritty');
    expect(entryReads()).toBe(1);

    now = 61_000;
    await icons.iconFile('/usr/bin/alacritty');
    expect(entryReads()).toBe(2);
  });
});

// The fake file system is itself logic the tests above lean on.
describe('fakeFs', () => {
  it('lists the names directly inside a directory and follows links', async () => {
    const { fs } = fakeFs({ '/a/b/c.txt': '', '/a/d.txt': '' }, { '/x': '/a/d.txt' });
    expect((await fs.list('/a')).sort()).toEqual(['b', 'd.txt']);
    expect(await fs.realpath('/x')).toBe('/a/d.txt');
    expect(await fs.realpath('/missing')).toBeNull();
  });
});
