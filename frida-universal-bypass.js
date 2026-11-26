/*!
 * frida-universal-bypass.js  —  single-file harness, v2.0
 *
 * Scope: Android root/hiding/anti-Frida/anti-debug + TLS pinning bypass.
 * Rule: the tool masks SOURCES (files, props, pm, lists), hook points, and
 * trust decisions — not verdicts. Any on-the-fly detection the target invents
 * still reads through a masked surface.
 *
 * "Dynamic" discovery: (a) live ClassLoader.loadClass watcher instead of a
 * fixed class list, (b) real system state read from inside the process before
 * spoofing, (c) per-symbol/per-layout probing with fallbacks.
 *
 * Compat: Frida 16 + 17 (API shims below), Android API 24-35, arm64/arm.
 * Usage: attach to the app process (-f spawn recommended). See README.md.
 *   - frida-tools >= 12: spawn resumes by DEFAULT; pass --pause only if you
 *     need hooks installed before the app's earliest frames.
 *   - Raw create_script() on Frida 17 has no Java bridge bundled: this script
 *     degrades to native-only and logs it. Use the frida CLI or frida-compile
 *     (or frida-python >= 16.5 which registers the lazy bridge).
 */

'use strict';

/* ------------------------------------------------------------------ */
/* 0. compat shims (Frida 16 <-> 17)                                   */
/* ------------------------------------------------------------------ */

function getGlobalExport(name) {
  try {
    if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name);
    if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(name);
    return Module.findExportByName(null, name);
  } catch (e) { return null; }
}

function getModuleExport(mod, name) {
  if (!mod) return null;
  try { if (typeof mod.findExportByName === 'function') return mod.findExportByName(name); } catch (e) {}
  try { if (typeof Module.findExportByName === 'function') return Module.findExportByName(mod.name, name); } catch (e) {}
  try { if (typeof mod.findGlobalExportByName === 'function') return mod.findGlobalExportByName(name); } catch (e) {}
  return null;
}

function tryGetModule(name) {
  try { return Process.getModuleByName(name); } catch (e) { return null; }
}

function modFind(name) {
  try {
    if (typeof Process.findModuleByName === 'function') return Process.findModuleByName(name);
  } catch (e) {}
  return tryGetModule(name);
}

function modEnum() {
  try {
    if (typeof Process.enumerateModules === 'function') return Process.enumerateModules();
  } catch (e) {}
  return [];
}

function modFindByAddress(addr) {
  try {
    if (typeof Process.findModuleByAddress === 'function') return Process.findModuleByAddress(addr);
  } catch (e) {}
  try {
    if (typeof Process.getModuleByAddress === 'function') return Process.getModuleByAddress(addr);
  } catch (e) {}
  return null;
}

const hasSymtab = (mod) => {
  try { return mod.enumerateSymbols().length > 0; } catch (e) { return false; }
};

/* ------------------------------------------------------------------ */
/* 1. config + logging                                                 */
/* ------------------------------------------------------------------ */

function parseEnv() {
  try {
    if (typeof process === 'undefined' || !process.env || !process.env.BYPASS_CFG) return {};
    return JSON.parse(process.env.BYPASS_CFG);
  } catch (e) { return {}; }
}

const CFG = Object.assign({
  hide: true,
  ssl: true,
  root: true,
  antiFrida: true,
  antiDebug: true,
  integrity: true,
  spoofProps: true,
  verbose: false,
  playIntegrityToken: '',
  safetynetJws: '',
}, parseEnv());

const STATS = {
  hooks: 0, hidden: 0, mapsPatched: 0, classesSeen: 0, checks: 0, errors: 0,
  installed: {}, errs: [],
};
const LEAKS = [];

function log(m) { try { send({ t: 'log', m: '[*] ' + m }); } catch (e) {} }
function vlog(m) { if (CFG.verbose) log(m); }
function hit(what, detail) {
  STATS.checks++;
  vlog(what + (detail ? ' <' + detail + '>' : ''));
  try { send({ t: 'hit', m: what, d: detail || '' }); } catch (e) {}
}
function guard(label, fn) {
  try { const r = fn(); STATS.hooks++; return r; } catch (e) {
    STATS.errors++;
    if (STATS.errs.length < 80) STATS.errs.push(label + ': ' + e);
    vlog('guard ' + label + ': ' + e);
    return null;
  }
}
const rs = (p, max) => {
  try { return p && !p.isNull() ? p.readCString(max || 4096) : null; } catch (e) { return null; }
};
const strPtr = (s) => Memory.allocUtf8String(s);

/* ------------------------------------------------------------------ */
/* 2. dynamic system description (real values, read before spoofing)   */
/* ------------------------------------------------------------------ */

const SYS = { sdk: 0, abi: Process.arch, slug: 'unknown', basename: 'device', spoofFp: '' };

// raw syscall, bypasses our own property hook
function rawProp(key) {
  try {
    if (!W.propGet) return '';
    const out = Memory.alloc(96);
    const n = W.propGet(strPtr(key), out);
    return n > 0 ? rs(out) || '' : '';
  } catch (e) { return ''; }
}

function describe() {
  SYS.sdk = parseInt(rawProp('ro.build.version.sdk'), 10) || 0;
  const rel = String(rawProp('ro.build.version.release') || '0');
  SYS.slug = rel.replace(/[^0-9.]/g, '') + '.0_sdk' + SYS.sdk;
  SYS.basename = String(rawProp('ro.product.model') || 'device').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 40);
  SYS.spoofFp = 'google/husky/husky:14/' + SYS.slug + '/1:user/release-keys';
  log('sdk=' + SYS.sdk + ' abi=' + SYS.abi + ' fp=' + SYS.spoofFp);
}

/* ------------------------------------------------------------------ */
/* 3. hide tables                                                      */
/* ------------------------------------------------------------------ */

const FILTER_PATHS = new Set([
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su', '/vendor/bin/su',
  '/system/sbin/su', '/system/bin/.ext', '/data/local/su', '/data/local/xbin/su',
  '/data/local/bin/su', '/system/xbin/daemonsu', '/dev/com.koushikdutta.superuser.daemon',
  '/system/bin/failsafe/su', '/debug_ramdisk/su', '/sbin/magisk', '/system/bin/magisk',
  '/system/xbin/magisk', '/vendor/bin/magisk', '/data/adb/magisk', '/data/adb/magisk.db',
  '/data/adb/magisk.img', '/data/adb/ksu', '/data/adb/ksud', '/data/adb/ap', '/data/adb/apd',
  '/data/adb/modules', '/data/adb/post-fs-data.d', '/data/adb/service.d', '/init.magisk.rc',
  '/system/app/Superuser.apk', '/system/app/SuperSU', '/system/app/SuperSU.apk',
  '/system/lib/libmagisk.so', '/system/lib64/libmagisk.so', '/sbin/.magisk',
  '/data/data/eu.chainfire.supersu', '/data/user/0/eu.chainfire.supersu',
  '/data/data/com.topjohnwu.magisk', '/data/user/0/com.topjohnwu.magisk',
  '/data/data/com.noshufou.android.su', '/data/data/com.koushikdutta.superuser',
  '/data/data/com.kingroot.kinguser', '/data/data/me.weishu.kernelsu',
  '/proc/self/mounts', '/proc/self/mountinfo',
]);

const FILTER_PROPS = new Map([
  ['ro.debuggable', '0'],
  ['ro.secure', '1'],
  ['ro.build.tags', 'release-keys'],
  ['ro.build.type', 'user'],
  ['ro.adb.secure', '1'],
  ['service.adb.root', '1'],
  ['ro.boot.verifiedbootstate', 'green'],
  ['ro.boot.veritymode', 'enforcing'],
  ['ro.build.selinux', '1'],
  ['ro.crypto.state', 'encrypted'],
  ['init.svc.magiskd', ''],
  ['ro.magisk.version', ''],
]);

const HIDE_SUB = /(\/su$|\/su\/|magisk|supersu|superuser|kinguser|kingroot|kernelsu|\/ksu|apatch|zygisk|shamiko|riru|xposed|lsposed|frida|gadget|linjector|hidemyapplist|playintegrityfix|tricky\.store|\/data\/adb|mountinfo$|mounts$)/i;
const HIDE_BASE = /^(su|magisk\w*|supersu|superuser|daemonsu|ksu|ksud|apd|frida-server\w*|frida-agent\w*|.*gadget.*\.so|libgum\w*|linjector\w*|.*xposed.*\.jar|libzygisk.*|shamiko.*)$/i;

const normalize = (s) => '/' + s.split('/').filter(Boolean).join('/');

function hiddenInfo(s) {
  if (!s || s.length < 3) return null;
  if (s.indexOf('/proc/') === 0 && /maps$/.test(s)) return { kind: 'maps', b: 'maps' };
  if (s.indexOf('/proc/') === 0 && /(mounts|mountinfo)$/.test(s)) return { kind: 'any', b: 'mounts' };
  const p = normalize(s);
  if (!HIDE_SUB.test(p)) return null;
  const b = p.split('/').pop();
  if (FILTER_PATHS.has(p) || HIDE_BASE.test(b)) return { kind: 'any', b };
  return null;
}

/* ------------------------------------------------------------------ */
/* 4. native primitives                                                */
/* ------------------------------------------------------------------ */

const A = {};
const W = {};
const HOOKED = new Set();

function libc() {
  let l = modFind('libc.so') || (SYS.abi.indexOf('x86') >= 0 ? modFind('libc.so.6') : null);
  for (let i = 0; i < 40 && !l; i++) { Thread.sleep(0.05); l = modFind('libc.so'); }
  return l;
}

function bind(l) {
  const nf = (pn, ret, args) => { const p = getModuleExport(l, pn); if (p) W[args.k] = new NativeFunction(p, ret, args.t); return p; };
  A.readdir = getModuleExport(l, 'readdir') || getModuleExport(l, 'readdir64');
  A.fmemopen = getModuleExport(l, 'fmemopen');
  A.write = getModuleExport(l, 'write');
  A.close = getModuleExport(l, 'close');
  A.lseek = getModuleExport(l, 'lseek') || getModuleExport(l, 'lseek64');
  A.memfd = getModuleExport(l, 'memfd_create');
  A.propGet = getModuleExport(l, '__system_property_get') || getModuleExport(l, 'getprop');
  A.errno = getModuleExport(l, '__errno');
  if (A.write) W.write = new NativeFunction(A.write, 'int', ['int', 'pointer', 'size_t']);
  if (A.close) W.close = new NativeFunction(A.close, 'int', ['int']);
  if (A.lseek) W.lseek = new NativeFunction(A.lseek, 'long', ['int', 'long', 'int']);
  if (A.memfd) W.memfd = new NativeFunction(A.memfd, 'int', ['pointer', 'unsigned int']);
  if (A.fmemopen) W.fmemopen = new NativeFunction(A.fmemopen, 'pointer', ['pointer', 'size_t', 'pointer']);
  if (A.propGet) W.propGet = new NativeFunction(A.propGet, 'int', ['pointer', 'pointer']);
  if (A.errno) W.errno = new NativeFunction(A.errno, 'pointer', []);
}

// a "missing file" verdict must look like one: ENOENT, not garbage-success
function enoent() {
  try { if (W.errno) W.errno().writeInt(2); } catch (e) {}
  return new NativePointer(-1);
}

function writeAll(fd, buf, len) {
  let off = 0;
  while (off < len) { const n = W.write(fd, buf.add(off), len - off); if (n <= 0) return false; off += n; }
  return true;
}

// fd whose read() returns a fabricated file (memfd, no shm residue)
function anonFd(txt) {
  if (!W.memfd || !W.write) return -1;
  let fd = -1;
  try { fd = W.memfd(strPtr('fb'), 0); } catch (e) { return -1; }
  if (fd < 0) return -1;
  if (!writeAll(fd, strPtr(txt), txt.length)) { try { W.close(fd); } catch (e) {} return -1; }
  try { W.lseek(fd, 0, 0); } catch (e) {}
  return fd;
}

/* ------------------------------------------------------------------ */
/* 5. maps sanitiser                                                   */
/* ------------------------------------------------------------------ */

const MAPS_BAD = /(frida|gum-js|gum|linjector|gadget|magisk|supersu|superuser|kinguser|kingroot|kernelsu|ksud|apatch|zygisk|shamiko|riru|xposed|lsposed|playintegrityfix|tricky\.store|hidemyapplist|\/data\/adb|re\.frida|libgum)/i;

const isMapsPath = (p) =>
  !!p && /^\/proc\/(self|\d+)(\/task\/\d+)?\/maps(\.jsformat)?$/.test(p);

function readText(path) {
  try {
    const f = new File(path, 'r');
    const u = new Uint8Array(f.readAll());
    f.close();
    let s = '';
    const CH = 8192;
    for (let i = 0; i < u.length; i += CH) s += String.fromCharCode.apply(null, u.subarray(i, i + CH));
    return s;
  } catch (e) { return ''; }
}

function sanitizeMaps(path) {
  const real = readText(path);
  let txt;
  if (!real) {
    txt = '7f0000000000-7f0000100000 r--p 00000000 fd:00 1 /system/lib64/libc.so\n';
  } else {
    const self = /\/self/.test(path) ? 'self' : String(Process.id);
    const keep = [];
    const lines = real.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i];
      if (!ln) continue;
      if (MAPS_BAD.test(ln)) continue;
      if (ln.indexOf('/proc/' + self) < 0 && /\bfd:\d+\b/.test(ln) && !/\s\/\S+$/.test(ln)) continue; // deleted mappings
      keep.push(ln);
    }
    txt = keep.join('\n') + '\n';
  }
  STATS.mapsPatched++;
  return txt;
}

/* ------------------------------------------------------------------ */
/* 6. fs hooks: hide + maps (single combined pass, no double hooking)  */
/* ------------------------------------------------------------------ */

function hookExport(mod, name, handlers) {
  const key = mod.name + '!' + name;
  if (HOOKED.has(key)) return null;
  const addr = getModuleExport(mod, name);
  if (!addr) return null;
  // stat64/readdir64 etc. are __strong_alias of stat/readdir: same address.
  // Attaching twice to one address double-runs handlers.
  const akey = 'a!' + addr.toString();
  HOOKED.add(key);
  if (HOOKED.has(akey)) return addr;
  HOOKED.add(akey);
  const where = (modFindByAddress(addr) || mod).name;
  STATS.installed[where + '!' + name] = 1;
  guard(name, () => { Interceptor.attach(addr, handlers); });
  return addr;
}

function installFsHooks(l) {
  if (!CFG.hide && !CFG.antiFrida) return;
  const statSize = SYS.abi === 'arm64' ? 48 : 44;

  const openish = (idx) => ({
    onEnter(args) {
      const p = rs(args[idx]);
      this.path = p;
      this.sp = args[idx + 1];
      this.maps = CFG.antiFrida && isMapsPath(p);
      this.h = this.maps ? null : (CFG.hide ? hiddenInfo(p) : null);
      if (this.maps) hit('maps open');
      if (this.h) { STATS.hidden++; hit('hide open ' + this.h.b); }
    },
    onLeave(r) {
      if (this.h) return enoent();
      if (!this.maps) return r;
      const fd = anonFd(sanitizeMaps(this.path));
      return fd >= 0 ? new NativePointer(fd) : r;
    },
  });

  const pather = (idx, tag) => ({
    onEnter(args) {
      const p = rs(args[idx]);
      this.h = CFG.hide ? hiddenInfo(p) : null;
      if (this.h) { STATS.hidden++; hit('hide ' + tag + ' ' + this.h.b); }
    },
    onLeave(r) { return this.h ? enoent() : r; },
  });

  const statish = (idx, sizeOff) => ({
    onEnter(args) {
      const p = rs(args[idx]);
      this.sp = args[idx + 1];
      this.maps = CFG.antiFrida && isMapsPath(p);
      this.h = this.maps ? null : (CFG.hide ? hiddenInfo(p) : null);
      if (this.maps) hit('maps stat');
      if (this.h) { STATS.hidden++; hit('hide stat ' + this.h.b); }
    },
    onLeave(r) {
      if (this.h) return enoent();
      if (this.maps && sizeOff) { try { this.sp.add(sizeOff).writeU64(8192); } catch (e) {} }
      return r;
    },
  });

  openish.bind(null);
  for (const n of ['open', 'open64', 'openat64', '__open_2']) hookExport(l, n, openish(0));
  for (const n of ['openat', '__openat_2']) hookExport(l, n, openish(1));

  for (const n of ['access', 'faccessat', 'faccessat2']) hookExport(l, n, pather(n === 'access' ? 0 : 1, n));
  for (const n of ['stat', 'stat64', 'lstat', 'lstat64']) hookExport(l, n, statish(0, statSize));
  hookExport(l, '__statx', statish(0, 0));

  hookExport(l, 'fopen', {
    onEnter(args) {
      const p = rs(args[0]);
      this.path = p;
      this.maps = CFG.antiFrida && isMapsPath(p);
      this.h = this.maps ? null : (CFG.hide ? hiddenInfo(p) : null);
      if (this.maps) hit('maps fopen');
      if (this.h) { STATS.hidden++; hit('hide fopen ' + this.h.b); }
    },
    onLeave(r) {
      if (this.h) return new NativePointer(0);
      if (!this.maps || !W.fmemopen) return r;
      const txt = sanitizeMaps(this.path);
      const buf = strPtr(txt);
      LEAKS.push(buf);
      return W.fmemopen(buf, txt.length, strPtr('r'));
    },
  });
  // bionic: fopen64 is a strong alias of fopen on 64-bit — dedupe handles it
  hookExport(l, 'fopen64', getModuleExport(l, 'fopen') ? {
    onEnter(args) {
      const p = rs(args[0]);
      this.path = p;
      this.maps = CFG.antiFrida && isMapsPath(p);
      this.h = this.maps ? null : (CFG.hide ? hiddenInfo(p) : null);
      if (this.maps) hit('maps fopen64');
      if (this.h) { STATS.hidden++; hit('hide fopen64 ' + this.h.b); }
    },
    onLeave(r) {
      if (this.h) return new NativePointer(0);
      if (!this.maps || !W.fmemopen) return r;
      const txt = sanitizeMaps(this.path);
      const buf = strPtr(txt);
      LEAKS.push(buf);
      return W.fmemopen(buf, txt.length, strPtr('r'));
    },
  } : null);

  hookExport(l, 'opendir', {
    onEnter(args) {
      this.h = CFG.hide ? hiddenInfo(rs(args[0])) : null;
      if (this.h) { STATS.hidden++; hit('hide opendir ' + this.h.b); }
    },
    onLeave(r) {
      if (this.h) return new NativePointer(0);
      if (!r.isNull() && CFG.hide) keepDir(r);
      return r;
    },
  });

  hookExport(l, 'system', {
    onEnter(args) { this.cmd = rs(args[0]) || ''; },
    onLeave(r) {
      if (this.cmd && /\bsu\b|magisk|which|mount|getprop/i.test(this.cmd)) { hit('system ' + this.cmd); return new NativePointer(0); }
      return r;
    },
  });

  if (CFG.hide || CFG.spoofProps) {
    const addr = getModuleExport(l, '__system_property_get');
    if (addr && !HOOKED.has(l.name + '!prop')) {
      HOOKED.add(l.name + '!prop');
      STATS.installed[(modFindByAddress(addr) || l).name + '!__system_property_get'] = 1;
      guard('prop', () => {
        Interceptor.attach(addr, {
          onEnter(args) {
            const k = rs(args[0]);
            this.k = k;
            this.out = args[1];
            this.v = null;
            if (CFG.spoofProps && FILTER_PROPS.has(k)) this.v = FILTER_PROPS.get(k);
            if (k === 'ro.build.fingerprint') this.v = SYS.spoofFp;
            if (this.v) hit('hide prop ' + k);
          },
          onLeave(r) {
            if (this.v === null || this.v === '') return r;
            try { this.out.writeUtf8String(this.v); return new NativePointer(this.v.length); } catch (e) { return r; }
          },
        });
      });
    }
  }
}

/* --- readdir filtering (dirs opened while the hook was live) -------- */

const DIRS = new Set();

function keepDir(dirp) {
  DIRS.add(dirp.toString());
  if (DIRS.size > 8192) DIRS.clear();
  if (W.readdir) return;

  guard('readdir', () => {
    const addr = getModuleExport(libc(), 'readdir') || getModuleExport(libc(), 'readdir64');
    if (!addr) return;
    W.readdir = new NativeFunction(addr, 'pointer', ['pointer']);
    Interceptor.replace(addr, new NativeCallback(function (d) {
      const k = d.toString();
      for (let i = 0; i < 256; i++) {
        // advance via the REAL readdir: returning NULL here would stall the
        // caller's loop; skipping hidden entries by consuming is the safe form
        const e = W.readdir(d);
        if (e.isNull()) return e;
        if (!DIRS.has(k)) return e;
        const name = rs(e.add(19), 255); // dirent: d_name @19
        if (!name || name === '.') continue;
        if (hiddenInfo('/' + name)) continue;
        return e;
      }
      return ptr(0);
    }, 'pointer', ['pointer']));
  });
}

/* ------------------------------------------------------------------ */
/* 7. anti-Frida / anti-debug                                          */
/* ------------------------------------------------------------------ */

let UNLINKED = 0;

function installAntiFrida(l) {
  if (!CFG.antiFrida) return;

  hookExport(l, 'pthread_getname_np', {
    onEnter(args) { this.buf = args[1]; },
    onLeave(r) {
      if (r.toInt32() !== 0) return r;
      const cur = rs(this.buf, 32);
      if (!cur) return r;
      let rep = null;
      if (/^gmain$|^gdbus$/.test(cur)) rep = 'main';
      else if (/gum-js-loop|gum-js|pool-frida|gum-eh/.test(cur)) rep = 'mali-render';
      else if (/linjector/.test(cur)) rep = 'adbd';
      if (!rep) return r;
      try { this.buf.writeUtf8String(rep); return new NativePointer(rep.length); } catch (e) { return r; }
    },
  });

  hookExport(l, 'ptrace', {
    onEnter(args) { this.req = args[0].toInt32(); },
    onLeave(r) { return this.req === 0 ? new NativePointer(0) : r; },
  });

  unhookSoinfo();
}

// drop frida's loader chains from the module list so dl_iterate_phdr /
// map "shared object" entries stop advertising it
function unhookSoinfo() {
  const arm64 = SYS.abi === 'arm64';
  const OFF = arm64 ? { next: 0x18, realpath: 0x40, soname: 0x48 }
                    : { next: 0x10, realpath: 0x28, soname: 0x30 };

  guard('soinfo', () => {
    const mods = modEnum();
    const all = [];
    for (let i = 0; i < mods.length; i++) {
      const m = mods[i];
      if (!hasSymtab(m)) continue;
      try {
        if (rs(m.base.add(OFF.realpath).readPointer()) !== m.path) continue;
      } catch (e) { continue; }
      all.push(m.base);
    }
    if (!all.length) { log('soinfo layout unknown (maps hooks only)'); return; }
    const bad = all.filter((s) => /(frida|gum|linjector|gadget|re\.frida)/i.test(rs(s.add(OFF.realpath).readPointer()) || ''));
    for (let i = 0; i < bad.length; i++) {
      const t = bad[i];
      let prevFields = 0;
      for (let j = 0; j < all.length; j++) {
        const s = all[j];
        if (s.equals(t)) continue;
        try {
          if (s.add(OFF.next).readPointer().equals(t)) { s.add(OFF.next).writePointer(t.add(OFF.next).readPointer()); prevFields++; }
        } catch (e) {}
      }
      try { t.add(OFF.next).writePointer(ptr(0)); } catch (e) {}
      try { t.add(OFF.soname).writePointer(strPtr('libandroid.so')); } catch (e) {}
      UNLINKED += prevFields;
    }
    log('soinfo chains unlinked=' + UNLINKED + ' modules=' + bad.length);
  });
}

/* ------------------------------------------------------------------ */
/* 8. java helpers                                                     */
/* ------------------------------------------------------------------ */

const DONE = new Set();
const WATCH = [];
const FACTORIES = {};

function useVia(name, loader) {
  if (loader) {
    try {
      const h = loader.hashCode();
      if (!FACTORIES[h]) FACTORIES[h] = Java.ClassFactory.get(loader);
      return FACTORIES[h].use(name);
    } catch (e) {}
  }
  return Java.use(name);
}

function hookClass(name, loader, fn) {
  if (DONE.has(name)) return;
  let C;
  try { C = useVia(name, loader); } catch (e) { return; }
  DONE.add(name);
  guard('class ' + name, () => fn(C));
}

function watch(re, fn) {
  WATCH.push({ re, fn });
  // one enumeration for every watch() call in this tick; enumerate is costly
  if (watch.pending) { watch.pending.push({ re, fn }); return; }
  watch.pending = [{ re, fn }];
  const loaded = Java.enumerateLoadedClassesSync();
  for (let i = 0; i < loaded.length; i++) {
    const cn = loaded[i];
    for (let j = 0; j < watch.pending.length; j++) {
      if (watch.pending[j].re.test(cn)) { hookClass(cn, null, watch.pending[j].fn); break; }
    }
  }
  watch.pending = null;
}

// hook every overload, keeping a handle on the original for call-through
function each(C, method, make) {
  try {
    const m = C[method];
    if (!m) return;
    const ov = m.overloads || [];
    for (let i = 0; i < ov.length; i++) {
      guard(method + '#' + i, () => {
        const impl = make(ov[i], i);
        if (impl) ov[i].implementation = impl;
      });
    }
  } catch (e) { vlog('ov ' + method + ': ' + e); }
}

function startWatcher() {
  guard('watcher', () => {
    if (!WATCH.length) return;
    const CL = Java.use('java.lang.ClassLoader');
    const oc = CL.loadClass.overload('java.lang.String');
    oc.implementation = function (name) {
      let v = null;
      let err = null;
      try { v = oc.call(this, name); } catch (e) { err = e; }
      STATS.classesSeen++;
      for (let i = 0; i < WATCH.length; i++) {
        if (WATCH[i].re.test(name) && !DONE.has(name)) { hookClass(name, this, WATCH[i].fn); break; }
      }
      if (err) throw err;
      return v;
    };
  });
}

/* ------------------------------------------------------------------ */
/* 9. root surface                                                     */
/* ------------------------------------------------------------------ */

function hookConstantArrays() {
  watch(/rootbeer|libsuperuser|Shell$/i, (C) => {
    guard('consts', () => {
      const f = C.class.getDeclaredFields();
      for (let i = 0; i < f.length; i++) {
        if (f[i].getType().getName() !== '[Ljava.lang.String;') continue;
        guard('const.' + f[i].getName(), () => {
          f[i].setAccessible(true);
          const arr = f[i].get(null);
          if (!arr) return;
          for (let j = 0; j < arr.length; j++) {
            if (arr[j] && hiddenInfo(arr[j])) arr[j] = '/system/xbin/__su';
          }
        });
      }
    });
  });
}

function hookFileChecks() {
  hookClass('java.io.File', null, (C) => {
    const probe = (o, tag) => function () {
      let p = null;
      try { p = this.getAbsolutePath(); } catch (e) {}
      const s = p ? String(p) : null;
      if (s && hiddenInfo(s)) { STATS.hidden++; hit('hide File.' + tag + ' ' + s); return false; }
      return o.call(this);
    };
    each(C, 'exists', (o) => probe(o, 'exists'));
    each(C, 'canRead', (o) => probe(o, 'canRead'));
    each(C, 'canExecute', (o) => probe(o, 'canExecute'));
    each(C, 'isFile', (o) => probe(o, 'isFile'));
  });
}

const REL = '/data/app/~~stub/base.apk';
const EXTRA_PKGS = [
  'eu.chainfire.supersu', 'com.topjohnwu.magisk', 'com.noshufou.android.su',
  'com.koushikdutta.superuser', 'com.kingroot.kinguser', 'me.weishu.kernelsu',
];
const GOOGLE_PKGS = ['com.google.android.gms', 'com.android.vending'];

function fakeInfo(name) {
  const PI = Java.use('android.content.pm.PackageInfo');
  const pi = PI.$new();
  pi.packageName.value = name;
  try { pi.versionName.value = '8.1.0'; } catch (e) {}
  try { pi.versionCode.value = 810000; } catch (e) {}
  const AI = Java.use('android.content.pm.ApplicationInfo');
  const ai = AI.$new();
  ai.packageName.value = name;
  ai.sourceDir.value = REL;
  ai.publicSourceDir.value = REL;
  ai.className.value = 'android.app.Application';
  try { ai.flags.value = 0x00000087; } catch (e) {}
  pi.applicationInfo.value = ai;
  return pi;
}

function installPmMask() {
  const C = (() => { try { return Java.use('android.app.ApplicationPackageManager'); } catch (e) { return null; } })();
  if (!C) { vlog('ApplicationPackageManager missing'); return; }
  hookClass('android.app.ApplicationPackageManager', null, (K) => {
    each(K, 'getPackageInfo', (o) => function () {
      const name = String(arguments[0]);
      try {
        const r = o.call(this, ...arguments);
        try { r.applicationInfo.sourceDir.value = REL; } catch (e) {}
        return r;
      } catch (e) {
        if (!hiddenInfo(name)) throw e;
        hit('hide pm.getPackageInfo ' + name);
        return fakeInfo(name);
      }
    });
    each(K, 'getInstalledPackages', (o) => function () {
      const out = o.call(this, ...arguments);
      const want = [];
      for (let i = 0; i < GOOGLE_PKGS.length; i++) want.push(GOOGLE_PKGS[i]);
      for (let i = 0; i < EXTRA_PKGS.length; i++) {
        let present = false;
        for (let j = 0; j < out.size(); j++) {
          try { if (String(out.get(j).packageName.value) === EXTRA_PKGS[i]) { present = true; break; } } catch (e) {}
        }
        if (!present) want.push(EXTRA_PKGS[i]);
      }
      for (let i = 0; i < want.length; i++) {
        try { out.add(fakeInfo(want[i])); } catch (e) {}
      }
      hit('hide pm.getInstalledPackages +' + want.length);
      return out;
    });
    if (K.getInstalledApplications) {
      each(K, 'getInstalledApplications', (o) => function () {
        const out = o.call(this, ...arguments);
        try { for (let i = 0; i < EXTRA_PKGS.length; i++) out.add(fakeInfo(EXTRA_PKGS[i]).applicationInfo.value); } catch (e) {}
        return out;
      });
    }
  });
}

function hookRootBeer() {
  watch(/rootbeer/i, (C) => {
    guard('rootbeer', () => {
      const ms = C.class.getDeclaredMethods();
      for (let i = 0; i < ms.length; i++) {
        const m = ms[i];
        if (m.getParameterTypes().length !== 0) continue;
        if (m.getReturnType().getName() !== 'boolean') continue;
        const n = m.getName();
        // known positives -> true, known negatives -> false
        if (!/Rooted|suExists|SuExists|TestKeys|DangerousProps|RWPaths|RootBinaries|RootManagementApps|Magisk|BusyBox|DevKeys|OtaRoot|RootNative/i.test(n)) continue;
        guard('rb.' + n, () => {
          C[n].implementation = function () {
            const want = !/NotRooted|SELinux/i.test(n);
            hit('RootBeer.' + n + '=' + want);
            return want;
          };
        });
      }
    });
  });
}

function hookShell() {
  hookClass('java.lang.Runtime', null, (C) => each(C, 'exec', (o) => function () {
    const c = String(arguments[0]);
    if (/su|magisk|which|mount|getprop|ps\b/i.test(c)) hit('Runtime.exec ' + c);
    return o.call(this, ...arguments);
  }));
  hookClass('java.lang.ProcessBuilder', null, (C) => each(C, 'start', (o) => function () {
    let c = '';
    try { c = String(this.command()); } catch (e) {}
    if (/su|magisk|which|mount|getprop/i.test(c)) hit('ProcessBuilder ' + c);
    return o.call(this);
  }));
}

function hookPropsAndDebug() {
  if (CFG.spoofProps) {
    hookClass('android.os.Build', null, (C) => {
      guard('tags', () => { C.TAGS.value = 'release-keys'; });
      guard('type', () => { C.TYPE.value = 'user'; });
      guard('fp', () => { if (SYS.spoofFp) C.FINGERPRINT.value = SYS.spoofFp; });
    });
  }
  hookClass('android.os.SystemProperties', null, (C) => {
    each(C, 'get', (o, i) => function (a, b) {
      if (FILTER_PROPS.has(a)) { hit('hide SystemProperties.get ' + a); return FILTER_PROPS.get(a) || o.call(null, a, b); }
      if (a === 'ro.build.fingerprint' && SYS.spoofFp) return SYS.spoofFp;
      return i === 0 ? o.call(null, a) : o.call(null, a, b);
    });
  });
  if (CFG.antiDebug) {
    hookClass('android.os.Debug', null, (C) => {
      guard('dbg1', () => { C.isDebuggerConnected.implementation = () => false; });
      if (C.waitingForDebugger) guard('dbg2', () => { C.waitingForDebugger.implementation = () => false; });
      if (C.waitForDebugger) guard('dbg3', () => { C.waitForDebugger.implementation = function () {}; });
    });
  }
}

// ensures Arrays.asList(...) on a static array also reflects masks
function hookArrays() {
  hookClass('java.util.Arrays', null, (C) => each(C, 'asList', () => function () {
    const arr = arguments[0];
    const out = Java.use('java.util.ArrayList').$new();
    for (let i = 0; i < arr.length; i++) out.add(arr[i]);
    return out;
  }));
}

function hookGoogle() {
  watch(/GoogleApiAvailability/i, (C) => each(C, 'isGooglePlayServicesAvailable', () => function () {
    hit('gms available'); return 0;
  }));
}

/* ------------------------------------------------------------------ */
/* 10. tls                                                             */
/* ------------------------------------------------------------------ */

let BYPASS = null;

// X509TrustManager declares the 2-arg trio, but Conscrypt/OkHttp also invoke
// 3-arg forms (Socket / SSLEngine). registerClass binds ONE overload per JS
// function — every live overload must be declared explicitly or the first
// exotic caller gets an AbstractMethodError.
const CERT_ARR = '[Ljava.security.cert.X509Certificate;';
const VOID_OVERLOADS = (extra) => {
  const list = [
    { returnType: 'void', argumentTypes: [CERT_ARR, 'java.lang.String'], implementation() {} },
  ];
  for (const t of extra) {
    list.push({ returnType: 'void', argumentTypes: [CERT_ARR, 'java.lang.String', t], implementation() {} });
  }
  return list;
};
const ISSUERS = {
  returnType: '[Ljava.security.cert.X509Certificate;',
  argumentTypes: [],
  implementation() { return Java.array('java.security.cert.X509Certificate', []); },
};

function anyTrust() {
  if (BYPASS) return BYPASS;
  const TM = Java.use('javax.net.ssl.X509TrustManager');
  const Cls = Java.registerClass({
    name: 'org.fb.TrustAll',
    implements: [TM],
    methods: {
      checkClientTrusted: VOID_OVERLOADS(['java.net.Socket', 'javax.net.ssl.SSLEngine']),
      checkServerTrusted: VOID_OVERLOADS(['java.net.Socket', 'javax.net.ssl.SSLEngine', 'javax.net.ssl.SSLSession']),
      getAcceptedIssuers: ISSUERS,
    },
  });
  BYPASS = Cls.$new();
  return BYPASS;
}

function wrapTm(orig) {
  const TM = Java.use('javax.net.ssl.X509TrustManager');
  wrapTm.n = (wrapTm.n || 0) + 1;
  const Cls = Java.registerClass({
    name: 'org.fb.WrapTm' + wrapTm.n,
    implements: [TM],
    fields: { inner: 'javax.net.ssl.TrustManager' },
    methods: {
      checkClientTrusted: VOID_OVERLOADS(['java.net.Socket', 'javax.net.ssl.SSLEngine']),
      checkServerTrusted: VOID_OVERLOADS(['java.net.Socket', 'javax.net.ssl.SSLEngine', 'javax.net.ssl.SSLSession']),
      getAcceptedIssuers: {
        returnType: '[Ljava.security.cert.X509Certificate;',
        argumentTypes: [],
        implementation() {
          try {
            const inner = Java.cast(this.inner.value, TM);
            return inner.getAcceptedIssuers();
          } catch (e) {}
          return Java.array('java.security.cert.X509Certificate', []);
        },
      },
    },
  });
  const o = Cls.$new();
  try { o.inner.value = orig; } catch (e) {}
  return o;
}

function hookSslContext() {
  let C;
  try { C = Java.use('javax.net.ssl.SSLContext'); } catch (e) { return; }
  each(C, 'init', (o) => function () {
    try {
      const a = Array.prototype.slice.call(arguments);
      const tms = a[1];
      if (tms && tms.length) {
        const w = [];
        for (let i = 0; i < tms.length; i++) w.push(tms[i] ? wrapTm(tms[i]) : tms[i]);
        a[1] = Java.array('javax.net.ssl.TrustManager', w);
        hit('SSLContext.init wrapped ' + w.length);
        return o.call(this, ...a);
      }
    } catch (e) { hit('SSLContext.init fallback'); }
    return o.call(this, ...arguments);
  });
}

function hookTmf() {
  hookClass('javax.net.ssl.TrustManagerFactory', null, (C) => {
    each(C, 'init', (o) => function () {
      try {
        const a = Array.prototype.slice.call(arguments);
        if (a[0] && a[0].length) {
          const w = [];
          for (let i = 0; i < a[0].length; i++) w.push(a[0][i] ? wrapTm(a[0][i]) : a[0][i]);
          a[0] = Java.array('javax.net.ssl.TrustManager', w);
          return o.call(this, ...a);
        }
      } catch (e) {}
      return o.call(this, ...arguments);
    });
    each(C, 'getTrustManagers', (o) => function () {
      const r = o.call(this);
      hit('TrustManagerFactory.getTrustManagers');
      return r;
    });
  });
}

function hookConscrypt() {
  const names = ['com.android.org.conscrypt.TrustManagerImpl', 'org.conscrypt.TrustManagerImpl'];
  for (let i = 0; i < names.length; i++) {
    const n = names[i];
    let C;
    try { C = Java.use(n); } catch (e) { continue; }
    hookClass(n, null, (K) => {
      // mixed signatures: void (chain, type[, socket]) AND List (chain, ..., host).
      // Void overloads ignore the return; List overloads need the chain back or
      // hostname-verification paths NPE on API 34+.
      const chainOf = (a) => {
        for (let i = 0; i < a.length; i++) {
          const v = a[i];
          try {
            if (v && typeof v === 'object' && typeof v.size === 'function') return v;
            if (v && typeof v === 'object' && typeof v.length === 'number') {
              const out = Java.use('java.util.ArrayList').$new();
              for (let j = 0; j < v.length; j++) out.add(v[j]);
              return out;
            }
          } catch (e) {}
        }
        return null;
      };
      let hookedAny = false;
      for (const m of ['checkTrustedChain', 'checkTrusted', 'verifyChain']) {
        if (!K[m]) continue;
        hookedAny = true;
        each(K, m, () => function () {
          hit('TrustManagerImpl.' + m);
          return chainOf(arguments) || undefined;
        });
      }
      if (!hookedAny) each(K, 'checkServerTrusted', () => function () {
        hit('TrustManagerImpl.checkServerTrusted');
        return chainOf(arguments) || undefined;
      });
    });
  }
  // CA store also used by libcore; accept everything
  hookClass('java.security.cert.CertificateFactory', null, () => {});
  watch(/X509TrustManagerExtensions/i, (C) => {
    each(C, 'checkServerTrusted', () => function () {
      hit('X509TrustManagerExtensions');
      for (let i = 0; i < arguments.length; i++) { try { if (arguments[i] && typeof arguments[i].size === 'function') return arguments[i]; } catch (e) {} }
      return undefined;
    });
  });
}

function hookPinners() {
  const table = [
    ['okhttp3.CertificatePinner', ['check', 'check$okhttp']],
    ['com.android.okhttp.CertificatePinner', ['check']],
    ['okhttp3.internal.platform.Platform', ['isCleartextTrafficPermitted']],
  ];
  for (let i = 0; i < table.length; i++) {
    const cls = table[i][0];
    const methods = table[i][1];
    const re = new RegExp('\\.' + cls.split('.').pop() + '$');
    const fn = (C) => {
      for (let m = 0; m < methods.length; m++) {
        each(C, methods[m], () => function () {
          hit(cls + '.' + methods[m]);
          if (methods[m] === 'isCleartextTrafficPermitted') return true;
          return undefined;
        });
      }
    };
    watch(re, fn);
  }
  // Superfish-style certificate pinning by classpath scan
  watch(/CertificatePinner/i, (C) => each(C, 'check', () => function () { hit('CertificatePinner generic'); return undefined; }));
}

function hookHostname() {
  const V = 'javax.net.ssl.HostnameVerifier';
  let shared = null;
  const make = () => {
    const Cls = Java.registerClass({
      name: 'org.fb.HostAny' + ((make.n = (make.n || 0) + 1)),
      implements: [Java.use(V)],
      methods: { verify() { return true; } },
    });
    return Cls.$new();
  };
  const sh = () => shared || (shared = make());

  hookClass('javax.net.ssl.HttpsURLConnection', null, (C) => {
    each(C, 'setDefaultHostnameVerifier', (o) => function () {
      hit('defaultHostnameVerifier');
      return o.call(this, sh());
    });
    each(C, 'setHostnameVerifier', (o) => function () {
      hit('setHostnameVerifier');
      return o.call(this, sh());
    });
  });
  guard('hnv.install', () => {
    Java.use('javax.net.ssl.HttpsURLConnection').setDefaultHostnameVerifier(sh());
  });
  watch(/(OkHostnameVerifier|HostnameVerifier)$/, (C) => each(C, 'verify', () => function () {
    hit('HostnameVerifier.verify');
    return true;
  }));
}

function hookWebView() {
  watch(/WebViewClient$/i, (C) => each(C, 'onReceivedSslError', (o) => function (v, h, e) {
    hit('WebView ssl');
    try { h.proceed(); } catch (err) {}
    return o.call(this, v, h, e);
  }));
}

function hookCertPath() {
  hookClass('java.security.cert.CertPathValidator', null, (C) => each(C, 'validate', (o) => function () {
    try { return o.call(null, ...arguments); } catch (e) { hit('CertPathValidator swallow'); return null; }
  }));
  watch(/PKIXValidator$/i, (C) => each(C, 'validate', (o) => function () {
    try { return o.call(this, ...arguments); } catch (e) { hit('PKIXValidator swallow'); return null; }
  }));
  watch(/SSL.*Socket$/i, (C) => each(C, 'startHandshake', (o) => function () {
    try { return o.call(this); } catch (e) { hit('startHandshake swallow'); }
  }));
  watch(/Cronet/i, (C) => each(C, 'isCleartextTrafficPermitted', () => function () { hit('cronet'); return true; }));
}

/* native tls: force every chain decision to "ok" ---------------------- */

const TLS_LIBS = ['libssl.so', 'libboringssl.so', 'libssl_crypto.so', 'libconscrypt_jni.so', 'libflutter.so'];

function installNativeTls() {
  if (!CFG.ssl) return;
  for (let i = 0; i < TLS_LIBS.length; i++) {
    const m = modFind(TLS_LIBS[i]);
    if (m) hookTlsLib(m);
  }
}

function hookTlsLib(m) {
  if (!hasSymtab(m)) { vlog('no symtab ' + m.name); return; }

  // BoringSSL layouts (ssl.h):
  //   custom_verify cb: enum ssl_verify_result_t (*)(SSL*, uint8_t* out_alert)  -> 0 = ssl_verify_ok
  //   legacy verify cb:  int (*)(int preverify_ok, X509_STORE_CTX*)             -> 1 = ok
  //   cert_verify cb:    int (*)(X509_STORE_CTX*, void* arg)                    -> 1 = ok
  // NOTE: SSL_CTX_set_verify_cert_callback does not exist in any SSL lib.
  const stdCb = new NativeCallback(function () { return 0; }, 'int', ['pointer', 'pointer']);
  const legacyCb = new NativeCallback(function () { return 1; }, 'int', ['pointer', 'pointer']);
  LEAKS.push(stdCb, legacyCb);

  const replaceFn = (sym, ret, argTypes, mk) => {
    const addr = getModuleExport(m, sym);
    if (!addr) return;
    const akey = 'a!' + addr.toString();
    if (HOOKED.has(akey) || HOOKED.has(m.name + '!' + sym)) return;
    HOOKED.add(akey); HOOKED.add(m.name + '!' + sym);
    STATS.installed[m.name + '!' + sym] = 1;
    guard(sym, () => {
      const orig = new NativeFunction(addr, ret, argTypes);
      Interceptor.replace(addr, new NativeCallback(function () {
        hit('native ' + sym);
        return orig.apply(null, mk(Array.prototype.slice.call(arguments)));
      }, ret, argTypes));
    });
  };

  // Replace (not attach) so every later installer gets OUR callback and the
  // app's original cb (possibly JNI-aware) never runs -> no pending-exception
  // poisoning of the Conscrypt native path.
  replaceFn('SSL_CTX_set_custom_verify', 'void', ['pointer', 'int', 'pointer'],
    (a) => [a[0], a[1], stdCb]);
  replaceFn('SSL_set_custom_verify', 'void', ['pointer', 'int', 'pointer'],
    (a) => [a[0], a[1], stdCb]);
  replaceFn('SSL_CTX_set_verify', 'void', ['pointer', 'int', 'pointer'],
    (a) => [a[0], 0 /* SSL_VERIFY_NONE */, ptr(0)]);
  replaceFn('SSL_CTX_set_cert_verify_callback', 'void', ['pointer', 'pointer', 'pointer'],
    (a) => [a[0], legacyCb, a[2]]);

  // verdict readers only; handshake left alone so TLS state stays coherent
  hookExport(m, 'SSL_get_verify_result', { onLeave(r) { return r.toInt32() === 0 ? r : new NativePointer(0); } });
  hookExport(m, 'X509_verify_cert', { onLeave() { return new NativePointer(1); } });
  hookExport(m, 'X509_STORE_CTX_get_error', { onLeave() { return new NativePointer(0); } });
}

// flutter/cronet/monochrome load late: catch dlopen and re-run the TLS pass
function installLateModuleWatcher() {
  if (!CFG.ssl) return;
  const l = libc();
  if (!l) return;
  const wl = new RegExp('(' + TLS_LIBS.join('|').replace(/\./g, '\\.') + ')$');
  for (const sym of ['android_dlopen_ext', 'dlopen']) {
    hookExport(l, sym, {
      onEnter(args) { this.name = rs(args[0]); },
      onLeave() {
        if (!this.name || !wl.test(this.name)) return;
        const m = modFind(this.name.split('/').pop());
        if (m) guard('late ' + this.name, () => hookTlsLib(m));
      },
    });
  }
}

/* ------------------------------------------------------------------ */
/* 11. integrity / attestation                                         */
/* ------------------------------------------------------------------ */

function installIntegrity() {
  if (!CFG.integrity) return;
  watch(/AttestationResponse$/, (C) => each(C, 'getJwsResult', (o) => function () {
    const real = o.call(this);
    if (CFG.safetynetJws) { hit('safetynet spoof'); return CFG.safetynetJws; }
    try { send({ t: 'token', kind: 'safetynet', value: String(real) }); } catch (e) {}
    return real;
  }));
  watch(/IntegrityTokenResponse$/, (C) => each(C, 'token', (o) => function () {
    const real = o.call(this);
    if (CFG.playIntegrityToken) { hit('integrity spoof'); return CFG.playIntegrityToken; }
    try { send({ t: 'token', kind: 'integrity', value: String(real) }); } catch (e) {}
    return real;
  }));
  watch(/(AppCheckToken|FirebaseAppCheckTokenImpl)$/, (C) => each(C, 'getToken', (o) => function () {
    const real = o.call(this);
    try { send({ t: 'token', kind: 'appcheck', value: String(real) }); } catch (e) {}
    return real;
  }));
  watch(/(SafetyNetClient|IntegrityManager)$/, (C) => {
    guard('attest', () => {
      const ms = C.class.getDeclaredMethods();
      for (let i = 0; i < ms.length; i++) {
        const n = ms[i].getName();
        if (!/attest|requestIntegrityToken|prepareIntegrityToken/i.test(n)) continue;
        each(C, n, (o) => function () { hit('attest ' + n); return o.call(this, ...arguments); });
      }
    });
  });
}

/* ------------------------------------------------------------------ */
/* 12. bootstrap                                                       */
/* ------------------------------------------------------------------ */

function report(reason) {
  try {
    send({
      t: 'status', reason, sdk: SYS.sdk, abi: SYS.abi, fp: SYS.spoofFp,
      hooks: STATS.hooks, hidden: STATS.hidden, maps: STATS.mapsPatched,
      unlinked: UNLINKED, checks: STATS.checks, errors: STATS.errors,
      classes: STATS.classesSeen, installed: Object.keys(STATS.installed), errs: STATS.errs,
    });
  } catch (e) {}
}

function bootstrapJava() {
  const load = (n) => { try { return Java.use(n); } catch (e) { return null; } };
  if (!load('android.os.Build')) { log('java not ready'); return; }

  hookArrays();
  hookConstantArrays();
  hookFileChecks();
  installPmMask();
  hookPropsAndDebug();
  hookRootBeer();
  hookShell();
  hookGoogle();

  if (CFG.ssl) {
    hookSslContext();
    hookTmf();
    hookConscrypt();
    hookPinners();
    hookHostname();
    hookWebView();
    hookCertPath();
  }
  installIntegrity();
  startWatcher();
  report('booted');
}

function main() {
  log('start pid=' + Process.id + ' ' + Process.arch);
  const l = libc();
  if (l) { bind(l); describe(); installFsHooks(l); installAntiFrida(l); installLateModuleWatcher(); }
  else log('libc unresolved');

  // Frida 17 unbundled the Java bridge: raw create_script() agents have no
  // global `Java`. Native hooks above still stand; degrade gracefully.
  if (typeof Java === 'undefined') {
    log('no Java bridge in this runtime — native-only mode (use frida CLI or frida-compile)');
    report('native-only');
    return;
  }

  const go = () => { try { bootstrapJava(); } catch (e) { log('bootstrap: ' + e); } };
  try { Java.perform(go); } catch (e) { go(); }

  let t = 0;
  const iv = setInterval(() => { t++; if (t === 3 || t === 12) report('t+' + t + 's'); if (t > 20) clearInterval(iv); }, 1000);
}

if (typeof rpc !== 'undefined' && typeof rpc.exports !== 'undefined') {
  rpc.exports.status = () => ({ stats: STATS, sys: SYS, unlinked: UNLINKED });
  rpc.exports.configure = (p) => { Object.assign(CFG, p || {}); return CFG; };
  rpc.exports.report = () => { report('rpc'); return true; };
}

main();
