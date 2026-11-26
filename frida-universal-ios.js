/*!
 * frida-universal-ios.js  —  single-file harness, v1.0
 *
 * Scope: iOS jailbreak detection + SSL pinning bypass, iPhone/iPad, iOS 13-18.
 * Rule: mask SOURCES (paths, dyld image list, sysctl records, trust verdicts),
 * not verdicts, so a check the app invents at runtime still resolves through a
 * masked surface.
 *
 * "Dynamic" discovery: (a) ApiResolver('objc') wildcard sweeps so private class
 * clusters (__NSURLSessionLocal) are found, not just the nominal class; (b) the
 * dyld image table is rebuilt from the live list and resynced on dlopen;
 * (c) runtime triage logs which subsystem each check used, with a backtrace.
 *
 * Compat: Frida 16 + 17 (bridge ladder below), arm64/arm64e.
 * Usage: frida -U -f com.example.app -l frida-universal-ios.js
 *   Native layer is complete before the Java-style ObjC bootstrap, so --pause
 *   is safe; without it early hooks may be missed. See README.md.
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
  try { if (typeof mod.findExportByName === 'function') { const p = mod.findExportByName(name); if (p) return p; } } catch (e) {}
  try { if (typeof Module.findExportByName === 'function') { const p = Module.findExportByName(mod.name, name); if (p) return p; } } catch (e) {}
  // private dylibs on iOS regularly lack a usable lookup path; scan the symtab
  try {
    const syms = mod.enumerateSymbols();
    for (let i = 0; i < syms.length; i++) if (syms[i].name === name) return syms[i].address;
  } catch (e) {}
  return null;
}

function modFind(name) {
  try {
    if (typeof Process.findModuleByName === 'function') return Process.findModuleByName(name);
  } catch (e) {}
  try { return Process.getModuleByName(name); } catch (e) { return null; }
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
  try { if (typeof Process.getModuleByAddress === 'function') return Process.getModuleByAddress(addr); } catch (e) {}
  return null;
}

/* ObjC bridge ladder: 16 = lazy global, 17 = bundled bridge only in tooling. */
const O = (typeof ObjC !== 'undefined') ? ObjC
  : (typeof globalThis !== 'undefined' && globalThis.ObjC) ? globalThis.ObjC
  : null;

const HAS_OBJC = !!O;
const objcReady = () => { try { return HAS_OBJC && O.available === true; } catch (e) { return false; } };

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
  jb: true,
  ssl: true,
  hide: true,
  dyld: true,
  antiFrida: true,
  antiDebug: true,
  triage: true,
  verbose: false,
}, parseEnv());

const STATS = {
  hooks: 0, hidden: 0, images: 0, checks: 0, errors: 0, classes: 0,
  installed: {}, errs: [], tried: [],
};
const LEAKS = [];

function log(m) { try { send({ t: 'log', m: '[*] ' + m }); } catch (e) {} }
function vlog(m) { if (CFG.verbose) log(m); }

// triage: which subsystem answered + who asked (ctx = the hook's `this`)
function hit(what, detail, ctx) {
  STATS.checks++;
  vlog(what + (detail ? ' <' + detail + '>' : ''));
  const rec = { t: 'hit', m: what, d: detail || '' };
  try {
    const bt = Thread.backtrace(ctx && ctx.context ? ctx.context : undefined, Backtracer.ACCURATE)
      .slice(0, 6)
      .map((a) => {
        try { const s = DebugSymbol.fromAddress(a); return (s && s.moduleName ? s.moduleName : '?') + '!' + (s.name || '?'); }
        catch (e) { return '?'; }
      });
    rec.bt = bt;
    STATS.tried.push(what + ' <- ' + (bt[0] || '?'));
  } catch (e) {}
  try { send(rec); } catch (e) {}
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

function enoent() {
  try { if (W.errno) W.errno().writeInt(2); } catch (e) {}
  return new NativePointer(-1);
}

/* ------------------------------------------------------------------ */
/* 2. jailbreak surface tables                                         */
/* ------------------------------------------------------------------ */

const JB_PATHS = [
  '/Applications/Cydia.app', '/Applications/Sileo.app', '/Applications/Zebra.app',
  '/Applications/Filza.app', '/Applications/Icy.app', '/Applications/blackra1n.app',
  '/Applications/RockApp.app', '/Applications/WinterBoard.app',
  '/Library/MobileSubstrate/MobileSubstrate.dylib', '/Library/MobileSubstrate/DynamicLibraries',
  '/usr/lib/substrate/SubstrateLoader.dylib', '/usr/lib/libsubstrate.dylib',
  '/usr/lib/libsubstitute.dylib', '/usr/lib/libhooker.dylib', '/usr/lib/TweakInject.dylib',
  '/usr/lib/libellekit.dylib', '/usr/libexec/cydia', '/usr/libexec/ellekit',
  '/usr/bin/cycript', '/usr/bin/ssh', '/usr/sbin/sshd', '/usr/libexec/sftp-server',
  '/usr/bin/dpkg', '/usr/bin/apt', '/bin/bash', '/bin/sh', '/etc/apt',
  '/etc/ssh/sshd_config', '/private/var/stash', '/private/var/lib/apt',
  '/private/var/tmp/cydia.log', '/var/cache/apt', '/var/lib/cydia', '/var/lib/dpkg/status',
  '/var/log/syslog', '/var/tmp/cydia.log',
  '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
  '/var/jb',
];

const JB_LEAF = /^(Cydia|Sileo|Zebra|Substrate|Substitute|ellekit|libellekit|libsubstrate|libsubstitute|libhooker|TweakInject|cydia|dpkg|apt|bash|sshd|ssh|frida|FridaGadget|blob\d*\w*)\.?(dylib|app)?$/i;
const JB_SUB = /(MobileSubstrate|libsubstrate|libsubstitute|libhooker|TweakInject|ellekit|Cydia\.app|Sileo\.app|Zebra\.app|Filza\.app|cydia|dpkg|\/var\/jb(\/|$)|substrate)/i;
const HIDE_SUB = /(frida|gum-js|libgum|gadget|ellekit|substrate|substitute|libhooker|TweakInject|blob\d+\.dylib|re\.frida)/i;

const JB_SCHEMES = /^(cydia|sileo|zebra|zbra|filza|activator|installer|undecimus|trollstore|sileo-beta):/i;

function normalize(p) {
  if (!p) return null;
  const parts = p.split('/').filter(Boolean);
  return '/' + parts.join('/');
}

function isJbPath(p) {
  if (!p || p.length < 3) return null;
  const n = normalize(p);
  if (!n) return null;
  if (n === '/var/jb') return { k: 'dir', b: 'var/jb' };
  if (n.indexOf('/var/jb/') === 0) return { k: 'any', b: n.split('/').pop() };
  for (let i = 0; i < JB_PATHS.length; i++) if (n === JB_PATHS[i] || n.indexOf(JB_PATHS[i] + '/') === 0) {
    return { k: 'any', b: n.split('/').pop() };
  }
  if (JB_SUB.test(n)) return { k: 'any', b: n.split('/').pop() };
  const leaf = n.split('/').pop();
  if (JB_LEAF.test(leaf)) return { k: 'any', b: leaf };
  return null;
}

const isHiddenImage = (p) => !!p && HIDE_SUB.test(p);

/* ------------------------------------------------------------------ */
/* 3. native primitives                                                */
/* ------------------------------------------------------------------ */

const A = {};
const W = {};
const HOOKED = new Set();

function libsystem() {
  let l = modFind('libsystem_kernel.dylib') || modFind('libSystem.B.dylib');
  for (let i = 0; i < 40 && !l; i++) {
    Thread.sleep(0.05);
    l = modFind('libsystem_kernel.dylib') || modFind('libSystem.B.dylib');
  }
  return l;
}

function bind(l) {
  A.readdir = getModuleExport(l, 'readdir');
  A.fmemopen = getModuleExport(l, 'fmemopen');
  A.write = getModuleExport(l, 'write');
  A.close = getModuleExport(l, 'close');
  A.lseek = getModuleExport(l, 'lseek');
  A.ftruncate = getModuleExport(l, 'ftruncate');
  A.shm = getModuleExport(l, 'shm_open');
  A.errno = getGlobalExport('__error');
  if (A.write) W.write = new NativeFunction(A.write, 'long', ['int', 'pointer', 'size_t']);
  if (A.close) W.close = new NativeFunction(A.close, 'int', ['int']);
  if (A.lseek) W.lseek = new NativeFunction(A.lseek, 'long', ['int', 'long', 'int']);
  if (A.ftruncate) W.ftruncate = new NativeFunction(A.ftruncate, 'int', ['int', 'long']);
  if (A.shm) W.shm = new NativeFunction(A.shm, 'int', ['pointer', 'int', 'unsigned short']);
  if (A.fmemopen) W.fmemopen = new NativeFunction(A.fmemopen, 'pointer', ['pointer', 'size_t', 'pointer']);
  if (A.errno) W.errno = new NativeFunction(A.errno, 'pointer', []);
}

function hookExport(mod, name, handlers) {
  const addr = (mod ? getModuleExport(mod, name) : null) || getGlobalExport(name);
  if (!addr) return null;
  const akey = 'a!' + addr.toString();
  if (HOOKED.has(key(mod, name)) || HOOKED.has(akey)) return addr;
  HOOKED.add(key(mod, name));
  HOOKED.add(akey);
  STATS.installed[(modFindByAddress(addr) || mod || { name: 'global' }).name + '!' + name] = 1;
  guard(name, () => { Interceptor.attach(addr, handlers); });
  return addr;
}

function key(mod, name) { return (mod ? mod.name : '?') + '!' + name; }

/* ------------------------------------------------------------------ */
/* 4. jailbreak file hooks                                             */
/* ------------------------------------------------------------------ */

// rootful + rootless path verdicts, plus directory-entry filtering
function installFsHooks(l) {
  if (!CFG.jb && !CFG.hide) return;

  const openish = (idx) => ({
    onEnter(args) {
      const p = rs(args[idx]);
      this.h = isJbPath(p);
      if (this.h) { STATS.hidden++; hit('jb open', p); }
    },
    onLeave(r) { return this.h ? enoent() : r; },
  });

  const statish = (idx) => ({
    onEnter(args) {
      this.h = isJbPath(rs(args[idx]));
      if (this.h) { STATS.hidden++; hit('jb stat', this.h.b); }
    },
    onLeave(r) { return this.h ? enoent() : r; },
  });

  for (const n of ['open', 'openat']) hookExport(l, n, openish(n === 'open' ? 0 : 1));
  for (const n of ['access', 'faccessat']) hookExport(l, n, openish(n === 'access' ? 0 : 1));
  for (const n of ['stat', 'stat64', 'lstat', 'lstat64']) hookExport(l, n, statish(0));
  for (const n of ['statfs', 'statfs64']) hookExport(l, n, statish(0));

  hookExport(l, 'opendir', {
    onEnter(args) { this.h = isJbPath(rs(args[0])); if (this.h) hit('jb opendir', this.h.b); },
    onLeave(r) {
      if (this.h) return enoent();
      if (!r.isNull()) keepDir(r);
      return r;
    },
  });

  hookExport(l, 'fopen', {
    onEnter(args) { this.h = isJbPath(rs(args[0])); if (this.h) hit('jb fopen', this.h.b); },
    onLeave(r) { return this.h ? new NativePointer(0) : r; },
  });

  hookExport(l, 'fork', {
    onEnter() { hit('fork'); },
    onLeave() { return new NativePointer(1); },
  });
}

const DIRS = new Set();

function keepDir(dirp) {
  DIRS.add(dirp.toString());
  if (DIRS.size > 8192) DIRS.clear();
  if (W.readdir) return;
  guard('readdir', () => {
    const addr = A.readdir || getGlobalExport('readdir');
    if (!addr) return;
    W.readdir = new NativeFunction(addr, 'pointer', ['pointer']);
    Interceptor.replace(addr, new NativeCallback(function (d) {
      const k = d.toString();
      for (let i = 0; i < 128; i++) {
        const e = W.readdir(d);
        if (e.isNull()) return e;
        if (!DIRS.has(k)) return e;
        const name = rs(e.add(21), 255); // Darwin dirent: d_name @21
        if (!name || name === '.') continue;
        if (isJbPath('/' + name)) continue;
        return e;
      }
      return ptr(0);
    }, 'pointer', ['pointer']));
  });
}

/* ------------------------------------------------------------------ */
/* 5. dyld image hiding.                                               */
/*   iOS 15+ (dyld4) reads an internal vector, not infoArray, so the   */
/*   three _dyld_* entry points must be replaced. Publishing the       */
/*   infoArray too covers dyld3 (<=14) and task_info() walkers.        */
/* ------------------------------------------------------------------ */

const IMG = { keep: [], published: null, patched: false };

function dyldInfos() {
  try {
    const p = getGlobalExport('_dyld_all_image_infos');
    if (!p) return null;
    // dyld3 exports a pointer variable, dyld4 exports the struct itself
    const direct = p.readU32();
    if (direct >= 1 && direct <= 4) return p;
    const cand = p.readPointer();
    if (!cand.isNull()) {
      const v = cand.readU32();
      if (v >= 1 && v <= 4) return cand;
    }
    return direct >= 1 && direct < 0x1000 ? p : null;
  } catch (e) { return null; }
}

function buildImageTable() {
  const origCount = getGlobalExport('_dyld_image_count');
  const origName = getGlobalExport('_dyld_get_image_name');
  const origHeader = getGlobalExport('_dyld_get_image_header');
  if (!origCount || !origName || !origHeader) { log('dyld entry points missing'); return false; }

  // captured once: after Interceptor.replace these names resolve to trampolines
  ORIG.dyldCount = new NativeFunction(origCount, 'uint', []);
  ORIG.dyldName = new NativeFunction(origName, 'pointer', ['uint']);
  ORIG.dyldHeader = new NativeFunction(origHeader, 'pointer', ['uint']);

  const total = ORIG.dyldCount();
  IMG.keep = [];
  let dropped = 0;

  for (let i = 0; i < total; i++) {
    let path = null;
    let hdr = ptr(0);
    try { path = rs(ORIG.dyldName(i)); } catch (e) {}
    try { hdr = ORIG.dyldHeader(i); } catch (e) {}
    if (path && isHiddenImage(path)) { dropped++; continue; }
    IMG.keep.push({ i, path, cpath: path ? strPtr(path) : null, real: hdr });
  }
  STATS.images = dropped;
  log('dyld images total=' + total + ' hidden=' + dropped);
  return true;
}

function publishInfoArray() {
  const infos = dyldInfos();
  if (!infos) return;
  guard('infoArray', () => {
    const count = infos.add(4).readU32();
    const arr = infos.add(8).readPointer();
    if (!count || arr.isNull()) return;

    const want = count - STATS.images;
    if (want <= 0) return;

    // own buffer: 3 pointers per dyld_image_info
    const buf = Memory.alloc(24 * want);
    LEAKS.push(buf);

    let w = 0;
    for (let i = 0; i < count && w < want; i++) {
      const src = arr.add(24 * i);
      const p = src.readPointer();
      let keep = true;
      try { const s = rs(src.add(8).readPointer()); keep = !isHiddenImage(s); } catch (e) {}
      if (!keep) continue;
      buf.add(24 * w).writePointer(p);
      buf.add(24 * w + 8).writePointer(src.add(8).readPointer());
      buf.add(24 * w + 16).writePointer(src.add(16).readPointer());
      w++;
    }

    infos.add(8).writePointer(ptr(0));
    infos.add(8).writePointer(buf);
    infos.add(4).writeU32(w);
    IMG.published = buf;
    hit('dyld infoArray published', String(w));
  });

  // dyld4 reads an internal vector: replace the public entry points with an
  // index mapper over the filtered table. Never returns a hidden slot.
  guard('dyld.replace', () => {
    const cAddr = getGlobalExport('_dyld_image_count');
    const nAddr = getGlobalExport('_dyld_get_image_name');
    const hAddr = getGlobalExport('_dyld_get_image_header');

    if (cAddr) {
      Interceptor.replace(cAddr, new NativeCallback(function () { return IMG.keep.length; }, 'uint', []));
      IMG.patched = true;
    }
    if (nAddr) {
      Interceptor.replace(nAddr, new NativeCallback(function (i) {
        const e = IMG.keep[Number(i)];
        return e ? (e.cpath || ptr(0)) : ptr(0);
      }, 'pointer', ['uint']));
    }
    if (hAddr) {
      Interceptor.replace(hAddr, new NativeCallback(function (i) {
        const e = IMG.keep[Number(i)];
        return e && e.real ? e.real : ptr(0);
      }, 'pointer', ['uint']));
    }
    hit('dyld entry points replaced', String(IMG.keep.length));
  });
}

/* resync from the captured originals after late dlopen; ASLR-stable, appends */
function resyncImages() {
  if (!CFG.dyld || !ORIG.dyldName || !IMG.patched) return;
  guard('dyld.resync', () => {
    const seen = new Set(IMG.keep.map((x) => x.path));
    const total = ORIG.dyldCount();
    for (let i = 0; i < total; i++) {
      let p = null;
      try { p = rs(ORIG.dyldName(i)); } catch (e) { break; }
      if (!p || seen.has(p)) continue;
      seen.add(p);
      if (isHiddenImage(p)) continue;
      let hdr = ptr(0);
      try { hdr = ORIG.dyldHeader(i); } catch (e) {}
      IMG.keep.push({ i, path: p, cpath: strPtr(p), real: hdr });
    }
  });
}

/* ------------------------------------------------------------------ */
/* 6. anti-Frida / anti-debug traps                                    */
/* ------------------------------------------------------------------ */

const TRAPS = {};
// impl receives the original NativeFunction: the address is patched after this,
// so re-resolving the export inside the callback would recurse forever
function trap(name, addr, ret, args, impl) {
  if (!addr || TRAPS[name]) return;
  TRAPS[name] = 1;
  guard('trap.' + name, () => {
    const orig = new NativeFunction(addr, ret, args);
    Interceptor.replace(addr, new NativeCallback(function () {
      return impl.apply(null, [orig].concat(Array.prototype.slice.call(arguments)));
    }, ret, args));
    STATS.installed['syscall!' + name] = 1;
  });
}

function installTraps(l) {
  if (CFG.antiDebug) {
    // PT_DENY_ATTACH(31) kills attach when a debugger already holds the task
    trap('ptrace', getGlobalExport('ptrace') || getModuleExport(l, 'ptrace'), 'int', ['int', 'int', 'pointer', 'pointer'],
      (orig, req, a1, a2, a3) => (req === 31 ? 0 : orig(req, a1, a2, a3)));
    trap('isatty', getGlobalExport('isatty') || getModuleExport(l, 'isatty'), 'int', ['int'], function () { return 0; });
    // getppid: 1 under launchd, !=1 under a spawn chain
    trap('getppid', getGlobalExport('getppid') || getModuleExport(l, 'getppid'), 'int', [], function () { return 1; });
  }

  // csops: CS_DEBUGGED lives in the status word written to arg2
  hookExport(l, 'csops', {
    onEnter(args) { this.buf = args[2]; this.len = args[3].toInt32(); },
    onLeave(r) {
      if (r.toInt32() !== 0 || !this.buf || this.len < 4) return r;
      try { this.buf.writeU32(this.buf.readU32() & ~0x10000000); } catch (e) {}
      return r;
    },
  });

  // sysctl: P_TRACED (0x800) in kinfo_proc p_flag @ +0x20; procargs path scrub
  const sysctl = getGlobalExport('sysctl') || getModuleExport(l, 'sysctl');
  hookExport(l, 'sysctl', {
    onEnter(args) {
      this.name = args[0];
      this.namelen = args[1].toInt32();
      this.oldp = args[2];
      this.oldlenp = args[3];
      this.isProc = this.namelen >= 2 && this.name.readInt() === 1 && this.name.add(4).readInt() === 14;
      this.isArgs = this.namelen >= 2 && this.name.readInt() === 1 && this.name.add(4).readInt() === 49;
    },
    onLeave(r) {
      if (r.toInt32() !== 0) return r;
      if (this.isProc) {
        try {
          const len = this.oldlenp.readULong();
          const n = Math.floor(Number(len) / 648); // sizeof(kinfo_proc) arm64
          for (let i = 0; i < n; i++) {
            const base = this.oldp.add(648 * i + 0x20); // p_flag
            base.writeU32(base.readU32() & ~0x800);
          }
          hit('sysctl KERN_PROC untraced', String(n));
        } catch (e) {}
      } else if (this.isArgs) {
        guard('procargs', () => {
          let len = 0;
          try { len = Number(this.oldlenp.readULong()); } catch (e) { return; }
          if (len < 64) return;
          const buf = this.oldp;
          const exec = rs(buf.add(16), 1024);
          if (!exec) return;
          if (isHiddenImage(exec)) {
            // fixed short path, stays inside the caller's buffer
            buf.add(16).writeUtf8String('/private/var/containers/Bundle/Application/x/App.app/App');
          }
          void sysctl;
        });
      }
      return r;
    },
  });

  // proc_pidinfo: pbi_flags bit 1 = PROC_FLAG_TRACED (offset 0 in bsdinfo)
  const ppi = getGlobalExport('proc_pidinfo') || getModuleExport(l, 'proc_pidinfo');
  hookExport(l, 'proc_pidinfo', {
    onEnter(args) { this.flavor = args[1].toInt32(); this.buf = args[3]; this.size = args[4].toInt32(); },
    onLeave(r) {
      if (r.toInt32() <= 0 || this.size < 8) return r;
      if (this.flavor !== 3 && this.flavor !== 13) return r;
      try { this.buf.writeU32(this.buf.readU32() & ~0x2); } catch (e) {}
      hit('proc_pidinfo flags');
      return r;
    },
  });

  // frida-server port probe
  const connect = getGlobalExport('connect') || getModuleExport(l, 'connect');
  hookExport(l, 'connect', {
    onEnter(args) {
      this.probe = false;
      try {
        const sa = args[1];
        if (sa.readU8() === 2) { // AF_INET
          const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
          if (port === 27042 || port === 27043) this.probe = true;
        }
      } catch (e) {}
      if (this.probe) hit('connect 27042');
    },
    onLeave(r) {
      if (!this.probe) return r;
      try { if (W.errno) W.errno().writeInt(61); } catch (e) {} // ECONNREFUSED
      return new NativePointer(-1);
    },
  });

  // task_get_exception_ports: extra handler means "debugger"
  const tgep = getGlobalExport('task_get_exception_ports');
  if (tgep) hookExport(l, 'task_get_exception_ports', {
    onEnter(args) { this.masks = args[2]; this.count = args[3]; },
  });
}

/* Mach/TASK_DYLD_INFO walkers read the same infoArray.
   struct task_dyld_info { addr@0, size@8, format@16 } */
function hookTaskDyld() {
  if (!CFG.dyld) return;
  guard('task_info', () => {
    const addr = getGlobalExport('task_info');
    if (!addr) return;
    ORIG.task_info = new NativeFunction(addr, 'int', ['uint', 'int', 'pointer', 'pointer']);
    Interceptor.attach(addr, {
      onEnter(args) { this.flavor = args[1].toInt32(); this.out = args[2]; },
      onLeave() {
        if (this.flavor !== 17 || !this.out) return;
        try {
          if (!IMG.published) return;
          this.out.add(0).writePointer(IMG.published);
        } catch (e) {}
        hit('task_info TASK_DYLD_INFO');
      },
    });
    STATS.installed['mach!task_info'] = 1;
  });
}

/* ------------------------------------------------------------------ */
/* 7. Security.framework trust verdicts                               */
/* ------------------------------------------------------------------ */

let SEC = null;
const ORIG = {};

function installSecurityHooks() {
  if (!CFG.ssl) return;
  SEC = modFind('Security') || modFind('Security.framework') || null;
  const g = (n) => (SEC ? getModuleExport(SEC, n) : getGlobalExport(n));

  // Deprecated (iOS <=13 SDK targets) but still live: both outputs must be
  // produced — success status AND kSecTrustResultProceed(1) in the out word.
  const ste = g('SecTrustEvaluate');
  if (ste) {
    ORIG.SecTrustEvaluate = new NativeFunction(ste, 'int', ['pointer', 'pointer']);
    hookExport(SEC, 'SecTrustEvaluate', {
      onEnter(args) { this.result = args[1]; hit('SecTrustEvaluate', null, this); },
      onLeave() {
        try { this.result.writeU32(1); } catch (e) {}
        return new NativePointer(0);
      },
    });
  }

  // iOS 12+ path: the CFErrorRef out-param is uninitialized stack the caller
  // will CFRelease, so it must be zeroed even on success.
  const stwe = g('SecTrustEvaluateWithError');
  if (stwe) {
    ORIG.SecTrustEvaluateWithError = new NativeFunction(stwe, 'bool', ['pointer', 'pointer']);
    hookExport(SEC, 'SecTrustEvaluateWithError', {
      onEnter(args) { this.err = args[1]; hit('SecTrustEvaluateWithError', null, this); },
      onLeave() {
        try { this.err.writePointer(ptr(0)); } catch (e) {}
        return new NativePointer(1);
      },
    });
  }

  // chain readers must not re-evaluate in between
  const cnt = g('SecTrustGetCertificateCount');
  if (cnt) hookExport(SEC, 'SecTrustGetCertificateCount', {
    onLeave(r) { return r.toInt32() > 0 ? r : new NativePointer(1); },
  });
}

/* old NSURLConnection convenience path */
function installAllowsAnyHttps() {
  if (!CFG.ssl || !objcReady()) return;
  guard('allowsAnyHTTPSCertificateForHost', () => {
    const C = O.classes.NSURLConnection;
    if (!C) return;
    const m = C['+ allowsAnyHTTPSCertificateForHost:'];
    if (!m) return;
    m.implementation = O.implement(m, function () { hit('allowsAnyHTTPSCertificateForHost'); return 1; });
  });
}

/* ------------------------------------------------------------------ */
/* 8. native TLS (Apple's libboringssl + friends)                     */
/* ------------------------------------------------------------------ */

function tlsModules() {
  const out = [];
  const mods = modEnum();
  for (let i = 0; i < mods.length; i++) {
    if (/libboringssl|libssl_crypto|libsscronet|libcoretls_cfhelpers|libnetwork\.dylib|libflutter|libssl\.dylib|libcrypto\.dylib/i.test(mods[i].name)) {
      out.push(mods[i]);
    }
  }
  return out;
}

function installNativeTls() {
  if (!CFG.ssl) return;
  const mods = tlsModules();
  if (!mods.length) vlog('no TLS libs yet');
  for (let i = 0; i < mods.length; i++) hookTlsLib(mods[i]);
}

const TLS_CB = {
  // ssl_verify_ok. BoringSSL layout: (SSL *ssl, uint8_t *out_alert)
  ok: new NativeCallback(function () { return 0; }, 'int', ['pointer', 'pointer']),
  // legacy SSL_CTX_set_verify convention is inverted: 1 = accept
  legacy: new NativeCallback(function () { return 1; }, 'int', ['pointer', 'pointer']),
  psk: null,
};
LEAKS.push(TLS_CB.ok, TLS_CB.legacy);

function hookTlsLib(m) {
  if (!m) return;
  const replace = (sym, ret, args, mk) => {
    const addr = getModuleExport(m, sym);
    const k = m.name + '!tls!' + sym;
    if (!addr || TRAPS[k]) return;
    TRAPS[k] = 1;
    guard('tls.' + sym, () => {
      const orig = new NativeFunction(addr, ret, args);
      Interceptor.replace(addr, new NativeCallback(function () {
        hit('tls ' + sym, m.name, null);
        return orig.apply(null, mk(Array.prototype.slice.call(arguments)));
      }, ret, args));
      STATS.installed[m.name + '!' + sym] = 1;
    });
  };

  // Replace (not attach) the setters: every later install then gets our
  // callback, and the app's own JNI/CF-aware callback never runs.
  replace('SSL_CTX_set_custom_verify', 'void', ['pointer', 'int', 'pointer'], (a) => [a[0], a[1], TLS_CB.ok]);
  replace('SSL_set_custom_verify', 'void', ['pointer', 'int', 'pointer'], (a) => [a[0], a[1], TLS_CB.ok]);
  // legacy path: SSL_VERIFY_NONE(0) + no callback disables verification outright
  replace('SSL_CTX_set_verify', 'void', ['pointer', 'int', 'pointer'], (a) => [a[0], 0, ptr(0)]);
  replace('SSL_set_verify', 'void', ['pointer', 'int', 'pointer'], (a) => [a[0], 0, ptr(0)]);

  // a non-NULL PSK identity makes Apple's BoringSSL skip cert verification
  const psk = getModuleExport(m, 'SSL_get_psk_identity');
  if (psk && !TRAPS[m.name + '!psk']) {
    TRAPS[m.name + '!psk'] = 1;
    guard('psk', () => {
      if (!TLS_CB.psk) { TLS_CB.psk = strPtr('frida'); LEAKS.push(TLS_CB.psk); }
      const fixed = TLS_CB.psk;
      Interceptor.replace(psk, new NativeCallback(function () { return fixed; }, 'pointer', ['pointer']));
      STATS.installed[m.name + '!SSL_get_psk_identity'] = 1;
    });
  }

  hookExport(m, 'SSL_get_verify_result', { onLeave(r) { return r.toInt32() === 0 ? r : new NativePointer(0); } });
  hookExport(m, 'X509_verify_cert', { onLeave() { return new NativePointer(1); } });
  hookExport(m, 'X509_STORE_CTX_get_error', { onLeave() { return new NativePointer(0); } });

  // CFNetwork / Network.framework trust hand-off: success return skips
  // evaluation entirely (the trust out-param is left alone)
  hookExport(m, 'tls_helper_create_peer_trust', { onLeave(r) { hit('tls_helper_create_peer_trust', null, this); return new NativePointer(0); } });
  hookExport(m, 'nw_tls_create_peer_trust', { onLeave(r) { hit('nw_tls_create_peer_trust', null, this); return new NativePointer(0); } });
}

/* late-loaded frameworks (Cronet, Flutter, third-party TLS).
   dlopen lives in libdyld.dylib — passing libsystem finds nothing. */
function installLateWatcher() {
  for (const sym of ['dlopen', 'dlopen$VARIANT']) {
    hookExport(null, sym, {
      onEnter(args) { this.name = rs(args[0]); },
      onLeave() {
        if (!this.name) return;
        if (/\.(dylib|framework\/)/.test(this.name)) {
          const base = this.name.split('/').pop();
          const m = modFind(base) || modFind(this.name);
          if (m) {
            guard('late ' + base, () => {
              if (/libboringssl|libssl|libsscronet|libflutter|libcrypto/i.test(base)) hookTlsLib(m);
              const sec = modFind('Security');
              if (sec && !SEC) { SEC = sec; installSecurityHooks(); }
            });
          }
        }
        if (CFG.dyld) resyncImages();
      },
    });
  }
}

/* ------------------------------------------------------------------ */
/* 9. ObjC level                                                       */
/* ------------------------------------------------------------------ */

const DONE = new Set();

// ApiResolver sweep: catches private cluster subclasses the nominal class
// never covers (__NSURLSessionLocal, AFURLSessionManagerTaskDelegate, ...)
function sweep(selectorPattern, handlers, tag) {
  guard('sweep ' + tag, () => {
    const r = new ApiResolver('objc');
    const matches = r.enumerateMatches(selectorPattern);
    for (let i = 0; i < matches.length; i++) {
      const addr = matches[i].address;
      const akey = 'a!' + addr.toString();
      if (HOOKED.has(akey)) continue;
      HOOKED.add(akey);
      guard(tag + '#' + i, () => { Interceptor.attach(addr, handlers); STATS.classes++; });
    }
    STATS.installed['objc!' + tag] = matches.length;
  });
}

// block-based session challenge: call the completion with a trusted credential
const CHALLENGE = {
  onEnter(args) {
    hit('didReceiveChallenge', 'block');
    try {
      const block = new O.Block(args[4]);
      const saved = block.implementation;
      block.implementation = (disp, cred) => saved(0, cred);

      const ch = new O.Object(args[3]);
      const trust = ch.protectionSpace().serverTrust();
      const cred = O.classes.NSURLCredential.credentialForTrust_(trust);
      ch.sender().useCredential_forAuthenticationChallenge_(cred, ch);
    } catch (e) { vlog('challenge: ' + e); }
  },
};

function installObjc() {
  guard('objc.init', () => {
    const RA = new ObjC.Object; void RA;
  });

  // session / webview challenges across every class that implements them
  sweep('-[* URLSession:didReceiveChallenge:completionHandler:]', CHALLENGE, 'URLSessionChallenge');
  sweep('-[* webView:didReceiveAuthenticationChallenge:completionHandler:]', CHALLENGE, 'webViewChallenge');

  // NSURLConnection: no block, answer via the sender
  sweep('-[* connection:willSendRequestForAuthenticationChallenge:]', {
    onEnter(args) {
      hit('willSendRequestForAuthenticationChallenge');
      try {
        const ch = new O.Object(args[2]);
        const trust = ch.protectionSpace().serverTrust();
        const cred = O.classes.NSURLCredential.credentialForTrust_(trust);
        ch.sender().useCredential_forAuthenticationChallenge_(cred, ch);
      } catch (e) {}
    },
  }, 'URLConnectionChallenge');

  // jailbreak: URL schemes — attach and force the verdict, never call back in
  sweep('-[* canOpenURL:]', {
    onEnter(args) {
      let s = '';
      try { s = new O.Object(args[2]).toString(); } catch (e) {}
      this._jb = JB_SCHEMES.test(s);
      if (this._jb) hit('canOpenURL', s, this);
    },
    onLeave(r) { if (this._jb) r.replace(ptr(1)); },
  }, 'canOpenURL');

  // jailbreak: file existence (ObjC mirror of the libc layer)
  sweep('-[* fileExistsAtPath:]', {
    onEnter(args) {
      let s = '';
      try { s = new O.Object(args[2]).toString(); } catch (e) {}
      this._jb = isJbPath(s);
      if (this._jb) hit('fileExistsAtPath', s, this);
    },
    onLeave(r) { if (this._jb) r.replace(ptr(0)); },
  }, 'fileExistsAtPath');

  sweep('-[* fileExistsAtPath:isDirectory:]', {
    onEnter(args) {
      let s = '';
      try { s = new O.Object(args[2]).toString(); } catch (e) {}
      this._jb = isJbPath(s);
      this._dir = args[3];
      if (this._jb) hit('fileExistsAtPath:isDirectory:', s, this);
    },
    onLeave(r) {
      if (!this._jb) return;
      try { this._dir.writeU8(0); } catch (e) {}
      r.replace(ptr(0));
    },
  }, 'fileExistsAtPathDir');

  sweep('-[* isWritableFileAtPath:]', {
    onEnter(args) {
      let s = '';
      try { s = new O.Object(args[2]).toString(); } catch (e) {}
      this._jb = /^\/(private|var|etc|bin|usr|Library|System)/.test(s) || isJbPath(s);
      if (this._jb) hit('isWritableFileAtPath', s, this);
    },
    onLeave(r) { if (this._jb) r.replace(ptr(1)); },
  }, 'isWritableFileAtPath');

  // pinning frameworks: return-value based, attach is enough
  sweep('-[* evaluateServerTrust:forDomain:]', {
    onEnter() { this._s = 1; },
    onLeave(r) { hit('evaluateServerTrust', null, this); r.replace(ptr(1)); },
  }, 'AFSecurityPolicy');

  sweep('-[* evaluateTrust:forHostname:]', {
    onEnter() { this._s = 1; },
    onLeave(r) { hit('TSKPinningValidator', null, this); r.replace(ptr(0)); }, // TSKTrustDecisionShouldAllowConnection
  }, 'TrustKit');

  // common RASP helper names
  sweep('-[* isJailbroken]', {
    onEnter() { this._s = 1; },
    onLeave(r) { hit('isJailbroken', null, this); r.replace(ptr(1)); },
  }, 'isJailbroken');

  sweep('-[* isJailBreak]', {
    onEnter() { this._s = 1; },
    onLeave(r) { hit('isJailBreak', null, this); r.replace(ptr(1)); },
  }, 'isJailBreak');

  sweep('-[* isJailbrokenDevice]', {
    onEnter() { this._s = 1; },
    onLeave(r) { hit('isJailbrokenDevice', null, this); r.replace(ptr(1)); },
  }, 'isJailbrokenDevice');

  installAllowsAnyHttps();
}

/* retry: with --pause, libobjc may not be mapped when the agent starts */
function bootstrapObjc(attempt) {
  if (!HAS_OBJC) { log('no ObjC bridge (Frida 17 raw create_script?) — native-only'); report('native-only'); return; }
  if (!objcReady()) {
    if (attempt > 60) { log('ObjC never became available'); report('objc-timeout'); return; }
    setTimeout(() => bootstrapObjc(attempt + 1), 250);
    return;
  }
  guard('objc-bootstrap', () => installObjc());
  report('objc-booted');
}

/* ------------------------------------------------------------------ */
/* 10. bootstrap                                                      */
/* ------------------------------------------------------------------ */

function report(reason) {
  try {
    send({
      t: 'status', reason, abi: Process.arch, pid: Process.id,
      hooks: STATS.hooks, hidden: STATS.hidden, images: STATS.images,
      checks: STATS.checks, errors: STATS.errors, classes: STATS.classes,
      objc: objcReady(), installed: Object.keys(STATS.installed), errs: STATS.errs,
    });
  } catch (e) {}
}

function main() {
  if (globalThis.__uniIosInstalled) { log('already installed'); return; }
  globalThis.__uniIosInstalled = 1;

  log('start pid=' + Process.id + ' ' + Process.arch);
  const l = libsystem();
  if (l) {
    bind(l);
    installFsHooks(l);
    installTraps(l);
    if (CFG.dyld) {
      guard('dyld.desc', () => { buildImageTable(); publishInfoArray(); });
      hookTaskDyld();
    }
    installSecurityHooks();
    installNativeTls();
    installLateWatcher();
  } else log('libsystem unresolved — file hooks skipped');

  // native layer is complete before any ObjC work happens
  setTimeout(() => bootstrapObjc(0), 0);

  let t = 0;
  const iv = setInterval(() => { t++; if (t === 3 || t === 12) report('t+' + t + 's'); if (t > 20) clearInterval(iv); }, 1000);
}

if (typeof rpc !== 'undefined' && typeof rpc.exports !== 'undefined') {
  rpc.exports.status = () => ({ stats: STATS, objc: objcReady() });
  rpc.exports.configure = (p) => { Object.assign(CFG, p || {}); return CFG; };
  rpc.exports.report = () => { report('rpc'); return true; };
  rpc.exports.triage = () => STATS.tried.slice(-80);
}

main();
