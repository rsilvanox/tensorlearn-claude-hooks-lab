// PreToolUse guard: keep the approved intent and the instructor tests unchanged on every
// write path (Edit/Write/MultiEdit, shell redirects, cp, mv, tee, scripts...) while
// leaving ordinary source edits and read-only commands alone. See contract.md.
//
// Design:
//  * Every candidate path is resolved against the event's cwd, normalised (`..`, `//`)
//    and then canonicalised through symlinks (also for paths that do not exist yet), so
//    `src/../intent.md` and `src/shortcut` resolve to the protected target.
//  * Bash commands are tokenised (quotes, escapes, operators, redirects, heredocs) and
//    each simple command is classified. Only the paths a command would WRITE are checked,
//    so `cat intent.md` is allowed while `printf x > intent.md` is denied.
//  * Anything we cannot interpret safely (malformed events, unresolved variables in a
//    write target, a command substitution that names a protected file...) is denied with
//    an explanation. Deciding only reads the filesystem; it never writes.
import fs from 'node:fs';
import path from 'node:path';

const PROTECTED_FILES = ['/workspace/intent.md'];
const PROTECTED_DIRS = ['/workspace/tests/instructor'];
const MAX_REASON = 2000;

const EDIT_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);
const READ_TOOLS = new Set(['Read', 'Glob', 'Grep', 'LS', 'WebFetch', 'WebSearch', 'TodoWrite', 'Task', 'Agent', 'ExitPlanMode']);

class Deny extends Error {}

function result(decision, reason) {
  let text = typeof reason === 'string' && reason.trim() ? reason : 'No reason available.';
  if (text.length > MAX_REASON) text = text.slice(0, MAX_REASON - 3) + '...';
  return {hookSpecificOutput: {hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: text}};
}

export function decide(event) {
  try {
    return evaluate(event);
  } catch (err) {
    if (err instanceof Deny) return result('deny', err.message);
    return result('deny', `Guard could not evaluate this call safely, so it is denied: ${err && err.message ? err.message : String(err)}`);
  }
}

// ---------------------------------------------------------------- event dispatch

function evaluate(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) throw new Deny('Malformed hook event: expected an object with tool_name, tool_input and cwd.');
  const {tool_name: tool, tool_input: input} = event;
  if (typeof tool !== 'string' || !tool) throw new Deny('Malformed hook event: tool_name must be a non-empty string.');
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new Deny(`Malformed hook event: tool_input for ${tool} must be an object.`);
  let cwd = null;
  if (event.cwd !== undefined && event.cwd !== null) {
    if (typeof event.cwd !== 'string' || !path.isAbsolute(event.cwd)) throw new Deny('Malformed hook event: cwd must be an absolute path.');
    cwd = path.resolve(event.cwd);
  }
  const ctx = makeContext(cwd);

  if (EDIT_TOOLS.has(tool)) {
    const field = tool === 'NotebookEdit' && typeof input.notebook_path === 'string' ? 'notebook_path' : 'file_path';
    const p = input[field];
    if (typeof p !== 'string' || !p) throw new Deny(`Malformed ${tool} call: ${field} must be a non-empty string.`);
    const hit = checkPath(ctx, p, {});
    if (hit) return result('deny', `${tool} blocked: ${hit}`);
    return result('allow', `${tool} of ${p} does not touch a protected file.`);
  }

  if (tool === 'Bash') {
    if (typeof input.command !== 'string') throw new Deny('Malformed Bash call: command must be a string.');
    if (!input.command.trim()) throw new Deny('Malformed Bash call: command is empty.');
    analyzeScript(ctx, input.command, 0);
    return result('allow', 'Bash command does not write to a protected file.');
  }

  if (READ_TOOLS.has(tool)) return result('allow', `${tool} is read-only.`);

  // Unknown tool: deny if it names a protected path in a path-like field.
  for (const key of ['file_path', 'path', 'notebook_path', 'target', 'destination']) {
    if (typeof input[key] === 'string' && input[key]) {
      const hit = checkPath(ctx, input[key], {});
      if (hit) return result('deny', `Unrecognised tool ${tool} targets a protected path: ${hit}`);
    }
  }
  return result('allow', `${tool} does not reference a protected path.`);
}

// ---------------------------------------------------------------- paths

function makeContext(cwd) {
  const files = unique(PROTECTED_FILES.flatMap(f => [f, canonical(f)]));
  const dirs = unique(PROTECTED_DIRS.flatMap(d => [d, canonical(d)]));
  const inodes = [];
  for (const f of PROTECTED_FILES) {
    try { const st = fs.statSync(f); inodes.push({dev: st.dev, ino: st.ino, name: f}); } catch { /* absent locally */ }
  }
  return {cwds: cwd ? [cwd] : [], cwdUnknown: !cwd, files, dirs, inodes};
}

function unique(list) { return [...new Set(list)]; }

function within(p, root) {
  return p === root || p.startsWith(root.endsWith('/') ? root : root + '/');
}

// Resolve symlinks for the longest existing prefix (and dangling links), keep the rest.
function canonical(p) {
  let cur = p;
  const rest = [];
  for (let i = 0; i < 64; i++) {
    try {
      const real = fs.realpathSync(cur);
      return rest.length ? path.join(real, ...rest) : real;
    } catch {
      try {
        const st = fs.lstatSync(cur);
        if (st.isSymbolicLink()) { cur = path.resolve(path.dirname(cur), fs.readlinkSync(cur)); continue; }
      } catch { /* does not exist */ }
      const parent = path.dirname(cur);
      if (parent === cur) break;
      rest.unshift(path.basename(cur));
      cur = parent;
    }
  }
  return p;
}

function absoluteCandidates(ctx, p) {
  if (typeof p !== 'string' || !p) throw new Deny('Empty path is ambiguous.');
  if (p.includes('\0')) throw new Deny('Path contains a NUL byte.');
  if (p === '~' || p.startsWith('~/')) p = path.join(process.env.HOME || '/root', p.slice(1));
  if (path.isAbsolute(p)) return [path.resolve(p)];
  if (ctx.cwdUnknown || !ctx.cwds.length) throw new Deny(`Relative path "${p}" cannot be resolved: the working directory is unknown.`);
  return unique(ctx.cwds.map(c => path.resolve(c, p)));
}

// Returns a reason string when the path is protected, otherwise null.
// ancestor: also treat directories that CONTAIN a protected target as protected (rm -r, mv).
function checkPath(ctx, p, {ancestor = false}) {
  for (const abs of absoluteCandidates(ctx, p)) {
    const hit = checkAbsolute(ctx, abs, ancestor);
    if (hit) return p === abs ? hit : `${hit} (requested as "${p}")`;
  }
  return null;
}

function checkAbsolute(ctx, abs, ancestor) {
  for (const c of unique([abs, canonical(abs)])) {
    const via = c === abs ? '' : ` (via symlink to ${c})`;
    for (const f of ctx.files) if (c === f) return `${abs}${via} is the protected approved intent.`;
    for (const d of ctx.dirs) if (within(c, d)) return `${abs}${via} is inside the protected instructor tests.`;
    if (ancestor) {
      for (const t of [...ctx.files, ...ctx.dirs]) {
        if (t !== c && within(t, c)) return `${abs}${via} contains the protected path ${t}.`;
      }
    }
  }
  if (ctx.inodes.length) {
    try {
      const st = fs.statSync(abs);
      for (const n of ctx.inodes) if (st.dev === n.dev && st.ino === n.ino) return `${abs} is a hard link to the protected ${n.name}.`;
    } catch { /* absent */ }
  }
  return null;
}

// ---------------------------------------------------------------- shell parsing

const SEPARATORS = new Set([';', '&&', '||', '|', '|&', '&', ';;', '(', ')', '`', '$(', '{', '}']);
const WRITE_REDIRS = new Set(['>', '>>', '>|', '&>', '&>>', '<>', '>&']);
const READ_REDIRS = new Set(['<', '<<', '<<-', '<<<', '<&']);
const OPERATORS = ['&>>', '<<<', '<<-', '&&', '||', '>>', '>|', '>&', '<&', '<>', '<<', '&>', '|&', ';;', '$(', '<(', '>(', '>', '<', '|', '&', ';', '(', ')', '`'];

function extractHeredocs(src) {
  const lines = src.split('\n');
  const out = [];
  const bodies = [];
  const pending = [];
  for (const line of lines) {
    if (pending.length) {
      const d = pending[0];
      if ((d.strip ? line.replace(/^\t+/, '') : line) === d.delim) { bodies.push(d.body.join('\n')); pending.shift(); }
      else d.body.push(line);
      continue;
    }
    out.push(line);
    const re = /<<(-?)[ \t]*(['"]?)([A-Za-z_][\w.-]*)\2/g;
    let m;
    while ((m = re.exec(line))) {
      if (m.index > 0 && line[m.index - 1] === '<') continue; // here-string <<<
      pending.push({delim: m[3], strip: m[1] === '-', body: []});
    }
  }
  for (const d of pending) bodies.push(d.body.join('\n'));
  return {src: out.join('\n'), bodies};
}

function tokenize(src) {
  const toks = [];
  let word = null;
  let complex = false;
  const ensure = () => { if (!word) word = {t: 'word', v: '', vars: false, glob: false}; };
  const flush = () => { if (word) { toks.push(word); word = null; } };
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') {
      if (src[i + 1] === '\n') { i += 2; continue; }
      ensure(); word.v += src[i + 1] ?? ''; i += 2; continue;
    }
    if (c === "'") {
      ensure();
      const j = src.indexOf("'", i + 1);
      if (j < 0) throw new Deny('Bash command has an unterminated single quote; denied as ambiguous.');
      word.v += src.slice(i + 1, j); i = j + 1; continue;
    }
    if (c === '"') {
      ensure(); i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < src.length && '"\\$`\n'.includes(src[i + 1])) { word.v += src[i + 1]; i += 2; continue; }
        if (src[i] === '$' || src[i] === '`') { word.vars = true; if (src[i] === '`' || src[i + 1] === '(') complex = true; }
        word.v += src[i]; i++;
      }
      if (i >= src.length) throw new Deny('Bash command has an unterminated double quote; denied as ambiguous.');
      i++; continue;
    }
    if (c === ' ' || c === '\t') { flush(); i++; continue; }
    if (c === '\n') { flush(); toks.push({t: 'op', v: ';'}); i++; continue; }
    if (c === '#' && !word) { while (i < src.length && src[i] !== '\n') i++; continue; }
    const op = OPERATORS.find(o => src.startsWith(o, i));
    if (op && !(op === '(' && word && word.v.endsWith('$'))) {
      if (op === '$(' || op === '`' || op === '<(' || op === '>(') complex = true;
      // `2>` / `10>>`: a pure-digit word right before a redirect is a file descriptor.
      if ((op[0] === '>' || op[0] === '<') && word && /^\d+$/.test(word.v) && !word.vars) word = null;
      flush();
      toks.push({t: 'op', v: op === '<(' || op === '>(' ? '(' : op});
      i += op.length;
      continue;
    }
    ensure();
    if (c === '$') word.vars = true;
    if ('*?[{'.includes(c)) word.glob = true;
    word.v += c; i++;
  }
  flush();
  return {toks, complex};
}

function splitSegments(toks) {
  const segs = [];
  let cur = {words: [], redirs: []};
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t === 'op' && SEPARATORS.has(t.v)) { if (cur.words.length || cur.redirs.length) segs.push(cur); cur = {words: [], redirs: []}; continue; }
    if (t.t === 'op' && (WRITE_REDIRS.has(t.v) || READ_REDIRS.has(t.v))) {
      const target = toks[i + 1];
      if (!target || target.t !== 'word') throw new Deny(`Redirect "${t.v}" without a target; denied as ambiguous.`);
      i++;
      if (WRITE_REDIRS.has(t.v) && !(t.v === '>&' && /^(\d+|-)$/.test(target.v))) cur.redirs.push({op: t.v, target});
      continue;
    }
    cur.words.push(t);
  }
  if (cur.words.length || cur.redirs.length) segs.push(cur);
  return segs;
}

function analyzeScript(ctx, command, depth) {
  if (depth > 4) throw new Deny('Shell command nests too deeply to analyse; denied as ambiguous.');
  const {src, bodies} = extractHeredocs(command);
  const {toks, complex} = tokenize(src);
  for (const seg of splitSegments(toks)) analyzeSegment(ctx, seg, depth);
  // Heredoc bodies may be fed to an interpreter; treat them like inline code.
  for (const body of bodies) {
    const hit = codeMentionsProtected(ctx, body);
    if (hit) throw new Deny(`Heredoc content references a protected file (${hit}); denied because it may be executed.`);
  }
  // Command substitutions are only partially understood: refuse if they name a protected file.
  if (complex) {
    const hit = codeMentionsProtected(ctx, src);
    if (hit) throw new Deny(`Command uses substitution and references a protected file (${hit}); denied as ambiguous.`);
  }
}

// ---------------------------------------------------------------- command classification

const WRAPPERS = new Set(['sudo', 'doas', 'env', 'command', 'builtin', 'exec', 'nohup', 'time', 'nice', 'stdbuf', 'timeout', 'xargs']);
const INTERPRETERS = /^(python[\d.]*|pypy[\d.]*|node|nodejs|deno|bun|ruby|perl|php|lua|Rscript|osascript)$/;
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish']);
const READ_ONLY = new Set(['cat', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'fgrep', 'rg', 'ag', 'wc', 'ls', 'stat', 'file',
  'diff', 'cmp', 'md5sum', 'sha1sum', 'sha256sum', 'shasum', 'cksum', 'echo', 'printf', 'test', '[', '[[', 'readlink', 'realpath',
  'cut', 'tr', 'nl', 'od', 'xxd', 'hexdump', 'strings', 'basename', 'dirname', 'pwd', 'true', 'false', 'which', 'type', 'du', 'df',
  'tree', 'jq', 'column', 'fold', 'rev', 'comm', 'join', 'paste', 'expand', 'unexpand', 'fmt', 'tac', 'bat', 'sleep', 'date', 'whoami', 'id']);
const RECURSIVE_WRITERS = new Set(['rm', 'rmdir', 'unlink', 'shred', 'chmod', 'chown', 'chgrp', 'chattr', 'setfacl']);
const PLAIN_WRITERS = new Set(['tee', 'touch', 'truncate', 'mkdir', 'mkfifo', 'mknod']);
const COPIERS = new Set(['cp', 'install', 'ln', 'link', 'rsync', 'scp']);
const GIT_SAFE = new Set(['status', 'diff', 'log', 'show', 'blame', 'ls-files', 'grep', 'rev-parse', 'branch', 'add', 'commit', 'fetch',
  'push', 'remote', 'config', 'describe', 'tag', 'shortlog', 'reflog', 'cat-file', 'ls-tree', 'help', 'version']);
const VALUE_OPTS = {
  cp: ['-S', '--suffix'], install: ['-m', '-o', '-g', '-S', '--mode', '--owner', '--group', '--suffix'], mv: ['-S', '--suffix'],
  ln: ['-S', '--suffix'], rsync: ['-e', '--rsh', '--exclude', '--include', '--filter', '-f'], scp: ['-P', '-i', '-o', '-F', '-c', '-l'],
  truncate: ['-s', '-r', '--size', '--reference'], touch: ['-d', '-t', '-r', '--date', '--reference'], mkdir: ['-m', '--mode'],
  tee: [], sed: ['-e', '-f', '--expression', '--file', '-l'], awk: ['-F', '-v', '-f'], sort: ['-o', '-k', '-t', '-T', '-S', '--output'],
  uniq: ['-f', '-s', '-w'], chmod: ['--reference'], chown: ['--reference', '--from'], chgrp: ['--reference'],
};

function positionals(words, valueOpts = []) {
  const out = [];
  let endOpts = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (!endOpts && w.v === '--') { endOpts = true; continue; }
    if (!endOpts && w.v.startsWith('-') && w.v !== '-') {
      if (valueOpts.includes(w.v)) i++;
      continue;
    }
    out.push(w);
  }
  return out;
}

function optionValue(words, names) {
  const found = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    for (const n of names) {
      if (w.v === n && words[i + 1]) found.push(words[i + 1]);
      else if (n.startsWith('--') && w.v.startsWith(n + '=')) found.push({...w, v: w.v.slice(n.length + 1)});
      else if (!n.startsWith('--') && n.length === 2 && w.v.startsWith(n) && w.v.length > 2 && !w.v.startsWith('--')) found.push({...w, v: w.v.slice(2)});
    }
  }
  return found;
}

// Check a path the command would write. Throws Deny when protected or ambiguous.
function writeTarget(ctx, word, what, {ancestor = false} = {}) {
  if (word.vars) throw new Deny(`${what} "${word.v}" depends on a shell variable or substitution; denied as ambiguous.`);
  if (word.v === '/dev/null' || word.v === '/dev/stdout' || word.v === '/dev/stderr' || word.v === '-') return;
  let p = word.v;
  let anc = ancestor;
  if (word.glob && /[*?[{]/.test(p)) {
    // A glob may expand to anything in its directory: check that directory as a container.
    const prefix = p.slice(0, p.search(/[*?[{]/));
    p = prefix.endsWith('/') ? prefix : (path.dirname(prefix) || '.');
    if (!p) p = '.';
    anc = true;
  }
  const hit = checkPath(ctx, p, {ancestor: anc});
  if (hit) throw new Deny(`${what} blocked: ${hit}`);
}

function stripWrappers(words) {
  let w = words.slice();
  let viaXargs = false;
  for (let guard = 0; guard < 16; guard++) {
    while (w.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(w[0].v)) w.shift(); // VAR=value prefixes
    if (!w.length) break;
    const name = path.basename(w[0].v);
    if (!WRAPPERS.has(name)) break;
    if (name === 'xargs') viaXargs = true;
    w.shift();
    while (w.length && (w[0].v.startsWith('-') || (name === 'env' && /^[A-Za-z_]\w*=/.test(w[0].v)))) {
      const opt = w.shift().v;
      if ((name === 'sudo' && ['-u', '-g', '-C', '-D'].includes(opt)) || (name === 'nice' && opt === '-n') ||
          (name === 'xargs' && ['-I', '-n', '-P', '-L', '-d', '-E', '-s', '-a'].includes(opt)) ||
          (name === 'timeout' && ['-s', '-k', '--signal', '--kill-after'].includes(opt)) || (name === 'stdbuf' && /^-[ioe]$/.test(opt)) ||
          (name === 'env' && ['-u', '-C', '-S'].includes(opt))) w.shift();
    }
    if (name === 'timeout' && w.length) w.shift(); // duration
  }
  return {words: w, viaXargs};
}

function analyzeSegment(ctx, seg, depth) {
  for (const r of seg.redirs) writeTarget(ctx, r.target, `Redirect "${r.op}" to`);

  const {words, viaXargs} = stripWrappers(seg.words);
  if (!words.length) return;
  const cmd = path.basename(words[0].v);
  const args = words.slice(1);
  const vopts = VALUE_OPTS[cmd] || [];

  if (viaXargs && (COPIERS.has(cmd) || RECURSIVE_WRITERS.has(cmd) || PLAIN_WRITERS.has(cmd) || cmd === 'mv' || cmd === 'sed' || cmd === 'perl')) {
    // Targets come from stdin and cannot be seen; only allow when explicit args stay clear.
    for (const a of positionals(args, vopts)) writeTarget(ctx, a, `xargs ${cmd} target`, {ancestor: true});
    if (ctx.cwds.some(c => checkAbsolute(ctx, c, true))) throw new Deny(`xargs ${cmd} receives its targets from stdin in a directory containing protected files; denied as ambiguous.`);
    return;
  }

  if (cmd === 'cd' || cmd === 'pushd') {
    const target = positionals(args)[0];
    if (!target) return;
    if (target.vars || target.v === '-') { ctx.cwdUnknown = true; return; }
    // Keep the previous cwd too: the cd might have run in a subshell.
    ctx.cwds = unique([...ctx.cwds, ...absoluteCandidates(ctx, target.v)]);
    return;
  }

  if (COPIERS.has(cmd) || cmd === 'mv') return copyLike(ctx, cmd, args);
  if (RECURSIVE_WRITERS.has(cmd)) { for (const a of positionals(args, vopts)) writeTarget(ctx, a, `${cmd} target`, {ancestor: true}); return; }
  if (PLAIN_WRITERS.has(cmd)) { for (const a of positionals(args, vopts)) writeTarget(ctx, a, `${cmd} target`); return; }

  if (cmd === 'dd') { for (const a of args) if (a.v.startsWith('of=')) writeTarget(ctx, {...a, v: a.v.slice(3)}, 'dd output'); return; }
  if (cmd === 'sort') { for (const o of optionValue(args, ['-o', '--output'])) writeTarget(ctx, o, 'sort output'); return; }
  if (cmd === 'uniq') { const p = positionals(args, vopts); if (p[1]) writeTarget(ctx, p[1], 'uniq output'); return; }
  if (cmd === 'curl' || cmd === 'wget') { for (const o of optionValue(args, ['-o', '-O', '--output', '--output-document'])) writeTarget(ctx, o, `${cmd} output`); return; }
  if (cmd === 'tar' || cmd === 'unzip' || cmd === 'cpio') return extractLike(ctx, cmd, args);

  if (cmd === 'sed') {
    const inPlace = args.some(a => /^-[a-zA-Z]*i/.test(a.v) || a.v.startsWith('--in-place'));
    if (!inPlace) return;
    const hasScriptOpt = args.some(a => ['-e', '-f', '--expression', '--file'].includes(a.v) || a.v.startsWith('--expression=') || a.v.startsWith('--file='));
    const files = positionals(args, vopts).slice(hasScriptOpt ? 0 : 1);
    for (const f of files) writeTarget(ctx, f, 'sed -i target');
    return;
  }

  if (/^(awk|gawk|mawk|nawk)$/.test(cmd)) {
    const pos = positionals(args, vopts);
    const hasF = args.some(a => a.v === '-f');
    if (!hasF && pos[0]) {
      const hit = codeMentionsProtected(ctx, pos[0].v);
      if (hit) throw new Deny(`${cmd} program references a protected file (${hit}).`);
    }
    if (args.some(a => a.v === 'inplace' || a.v === '-i')) for (const f of pos.slice(hasF ? 0 : 1)) writeTarget(ctx, f, `${cmd} inplace target`);
    return;
  }

  if (SHELLS.has(cmd)) {
    const code = inlineCode(args, ['-c']);
    if (code !== null) analyzeScript(ctx, code, depth + 1);
    return;
  }
  if (cmd === 'eval') { analyzeScript(ctx, args.map(a => a.v).join(' '), depth + 1); return; }

  if (INTERPRETERS.test(cmd)) {
    const code = inlineCode(args, ['-c', '-e', '-E', '-p', '-r', '--eval', '--print', '-pe', '-ne', '-pi', '-pie', '-i', '-n']);
    if (code !== null) {
      const hit = codeMentionsProtected(ctx, code);
      if (hit) throw new Deny(`Inline ${cmd} code references a protected file (${hit}); scripts may not modify it.`);
    }
    if (cmd === 'perl' && args.some(a => /^-[a-zA-Z]*i/.test(a.v))) {
      for (const a of args) if (!a.v.startsWith('-') && a.v !== code) writeTarget(ctx, a, 'perl -i target');
    }
    return;
  }

  if (cmd === 'git') return gitLike(ctx, args);

  if (cmd === 'find') {
    const actions = args.some(a => ['-delete', '-exec', '-execdir', '-ok', '-okdir', '-fprint', '-fprintf', '-fls', '-fprint0'].includes(a.v));
    if (!actions) return;
    const roots = [];
    for (const a of args) { if (a.v.startsWith('-') || a.v === '(' || a.v === '!') break; roots.push(a); }
    if (!roots.length) roots.push({v: '.', vars: false, glob: false});
    for (const r of roots) writeTarget(ctx, r, 'find with -delete/-exec over', {ancestor: true});
    return;
  }

  if (READ_ONLY.has(cmd)) return;

  // Unclassified command: allow unless it names a protected path (conservative).
  for (const a of args) {
    const v = a.v.includes('=') && a.v.startsWith('-') ? a.v.slice(a.v.indexOf('=') + 1) : a.v;
    if (!v || a.vars || v.startsWith('-')) continue;
    let hit = null;
    try { hit = checkPath(ctx, v, {}); } catch { /* unresolvable arg: not a path we can judge */ }
    if (hit) throw new Deny(`Cannot tell whether "${cmd}" modifies its arguments, and it names a protected path: ${hit}`);
  }
}

function inlineCode(args, flags) {
  for (let i = 0; i < args.length; i++) {
    const v = args[i].v;
    if (flags.includes(v)) return args[i + 1] ? args[i + 1].v : '';
    if (/^-[a-zA-Z]*[ce]$/.test(v) && args[i + 1]) return args[i + 1].v; // combined flags such as -pe
    if (v.startsWith('--eval=')) return v.slice(7);
    if (!v.startsWith('-')) return null; // script file: runs as a normal program
  }
  return null;
}

function copyLike(ctx, cmd, args) {
  const vopts = VALUE_OPTS[cmd] || [];
  const targetDirs = optionValue(args, ['-t', '--target-directory']);
  const pos = positionals(args, [...vopts, '-t', '--target-directory']);
  const isMove = cmd === 'mv';
  let sources;
  let dest;
  if (targetDirs.length) { sources = pos; dest = targetDirs[0]; }
  else if (pos.length >= 2) { sources = pos.slice(0, -1); dest = pos[pos.length - 1]; }
  else if (pos.length === 1 && (cmd === 'ln' || cmd === 'link')) { sources = pos; dest = {v: '.', vars: false, glob: false}; }
  else throw new Deny(`${cmd} needs a source and a destination; denied as ambiguous.`);

  // Destination itself (a file), and dest/<basename of each source> (when dest is a directory).
  writeTarget(ctx, dest, `${cmd} destination`);
  if (!dest.vars && !dest.glob) {
    for (const s of sources) {
      if (s.vars || s.glob) {
        // Unknown source names landing in dest: deny if dest directory contains protected files.
        writeTarget(ctx, {...dest, v: dest.v}, `${cmd} destination directory`, {ancestor: true});
        continue;
      }
      writeTarget(ctx, {...dest, v: path.join(dest.v, path.basename(s.v))}, `${cmd} destination`);
    }
  }
  if (isMove) for (const s of sources) writeTarget(ctx, s, 'mv source (moving it away changes it)', {ancestor: true});
}

function extractLike(ctx, cmd, args) {
  const extracting = cmd === 'unzip' || cmd === 'cpio' || args.some(a => /^-?[a-zA-Z]*x/.test(a.v) && !a.v.startsWith('--') || a.v === '--extract');
  if (!extracting) return;
  const dirs = optionValue(args, cmd === 'unzip' ? ['-d'] : ['-C', '--directory']);
  const dest = dirs.length ? dirs[dirs.length - 1] : {v: '.', vars: false, glob: false};
  writeTarget(ctx, dest, `${cmd} extraction into`, {ancestor: true});
}

function gitLike(ctx, args) {
  let i = 0;
  while (i < args.length && args[i].v.startsWith('-')) {
    if (args[i].v === '-C' && args[i + 1]) {
      const dir = args[i + 1];
      if (dir.vars) ctx.cwdUnknown = true;
      else ctx.cwds = unique(ctx.cwds.flatMap(c => [c, path.resolve(c, dir.v)]));
      i += 2; continue;
    }
    i += ['-c', '--git-dir', '--work-tree'].includes(args[i].v) ? 2 : 1;
  }
  const sub = args[i];
  if (!sub || GIT_SAFE.has(sub.v)) return;
  for (const a of positionals(args.slice(i + 1))) writeTarget(ctx, a, `git ${sub.v} path`, {ancestor: true});
}

// Does free-form code (python -c, heredoc, awk program...) name a protected path?
// Every path-like token is resolved against the cwd and its ancestors, so
// open('intent.md','w') or open('src/shortcut','w') is caught but src/intent.md is not.
function codeMentionsProtected(ctx, code) {
  const tokens = unique(code.match(/[A-Za-z0-9_./~@+-]+/g) || []).slice(0, 2000);
  const bases = [];
  for (const c of ctx.cwds) {
    let cur = c;
    for (;;) { bases.push(cur); const up = path.dirname(cur); if (up === cur) break; cur = up; }
  }
  for (const t of tokens) {
    if (!/[A-Za-z]/.test(t)) continue;
    const candidates = path.isAbsolute(t) ? [path.resolve(t)] : unique(bases).map(b => path.resolve(b, t));
    for (const abs of candidates) {
      const hit = checkAbsolute(ctx, abs, false);
      if (hit) return hit;
    }
  }
  return null;
}
