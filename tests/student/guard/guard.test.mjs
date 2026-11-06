// Regression tests for guard/guard.mjs. Every test asserts at least one deny, so the
// suite fails against a guard that allows everything; most also assert an allow, so it
// fails against a guard that denies everything.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {decide} from '../../../guard/guard.mjs';

const HAS_WORKSPACE = fs.existsSync('/workspace/intent.md');
const HAS_SYMLINK = (() => { try { return fs.lstatSync('/workspace/src/shortcut').isSymbolicLink(); } catch { return false; } })();

const bash = (command, cwd = '/workspace') => ({tool_name: 'Bash', tool_input: {command}, cwd});
const edit = (tool_name, file_path, cwd = '/workspace') => ({tool_name, tool_input: {file_path, old_string: 'a', new_string: 'b', content: 'x'}, cwd});

function decision(event) {
  const out = decide(event);
  assert.ok(!(out instanceof Promise), 'decide must be synchronous');
  assert.deepEqual(Object.keys(out), ['hookSpecificOutput']);
  const h = out.hookSpecificOutput;
  assert.deepEqual(Object.keys(h).sort(), ['hookEventName', 'permissionDecision', 'permissionDecisionReason']);
  assert.equal(h.hookEventName, 'PreToolUse');
  assert.ok(['allow', 'deny'].includes(h.permissionDecision));
  assert.equal(typeof h.permissionDecisionReason, 'string');
  assert.ok(h.permissionDecisionReason.length > 0 && h.permissionDecisionReason.length <= 2000);
  return h.permissionDecision;
}
const denies = (event, msg) => assert.equal(decision(event), 'deny', msg ?? JSON.stringify(event));
const allows = (event, msg) => assert.equal(decision(event), 'allow', msg ?? JSON.stringify(event));

test('direct writes to protected files are denied through Edit, Write and MultiEdit', () => {
  for (const tool of ['Edit', 'Write', 'MultiEdit']) {
    denies(edit(tool, '/workspace/intent.md'));
    denies(edit(tool, '/workspace/tests/instructor/check.mjs'));
    denies(edit(tool, '/workspace/tests/instructor/new-file.mjs'));
  }
  allows(edit('Edit', '/workspace/src/app.mjs'));
});

test('relative, dotted and doubled paths resolve to the protected target', () => {
  denies(edit('Write', 'intent.md'));
  denies(edit('Write', './intent.md'));
  denies(edit('Edit', '/workspace/src/../intent.md'));
  denies(edit('Edit', '/workspace//intent.md'));
  denies(edit('Edit', '/workspace/./tests/./instructor/check.mjs'));
  denies(edit('Write', '../intent.md', '/workspace/src'));
  denies(edit('Write', '../tests/instructor/check.mjs', '/workspace/src'));
  allows(edit('Write', 'app.mjs', '/workspace/src'));
});

test('a symlink to a protected file is treated as that file', {skip: !HAS_SYMLINK && 'needs /workspace/src/shortcut'}, () => {
  denies(edit('Write', '/workspace/src/shortcut'));
  denies(edit('Edit', 'src/shortcut'));
  denies(bash('printf x > src/shortcut'));
  denies(bash('cp src/app.mjs src/shortcut'));
  denies(bash('echo x | tee -a src/shortcut'));
  allows(bash('cat src/shortcut'));
});

test('shell redirects to protected files are denied', () => {
  denies(bash('printf changed > intent.md'));
  denies(bash('echo more >> intent.md'));
  denies(bash('echo x>intent.md'));
  denies(bash('echo x 2> intent.md'));
  denies(bash('echo x &> ./intent.md'));
  denies(bash('echo x > tests/instructor/check.mjs'));
  denies(bash('cd src && printf x > ../intent.md'));
  denies(bash('printf x > ../intent.md', '/workspace/src'));
  denies(bash("bash -c 'echo x > intent.md'"));
  allows(bash('printf x > src/app.mjs'));
  allows(bash('node --test > src/out.txt 2>&1'));
});

test('cp and mv into or out of protected files are denied', () => {
  denies(bash('cp src/app.mjs intent.md'));
  denies(bash('cp src/app.mjs /workspace/tests/instructor/check.mjs'));
  denies(bash('cp src/app.mjs tests/instructor/'));
  denies(bash('cp -t tests/instructor src/app.mjs'));
  denies(bash('mv src/app.mjs intent.md'), 'rename onto the intent');
  denies(bash('mv intent.md src/intent.md'), 'rename the intent away');
  denies(bash('mv tests/instructor /tmp/elsewhere'), 'move the instructor tests away');
  allows(bash('cp intent.md src/intent-copy.md'), 'copying out only reads the intent');
  allows(bash('mv src/app.mjs src/main.mjs'));
});

test('tee, scripts and other writers cannot change protected files', () => {
  denies(bash('echo x | tee intent.md'));
  denies(bash('echo x | tee -a intent.md'));
  denies(bash('echo x | tee src/log.txt tests/instructor/check.mjs'));
  denies(bash(`python3 -c "open('intent.md','w').write('x')"`));
  denies(bash(`python3 -c "open('/workspace/tests/instructor/check.mjs','a')"`));
  denies(bash(`node -e "require('fs').writeFileSync('intent.md','x')"`));
  denies(bash("python3 - <<'EOF'\nopen('intent.md', 'w').write('x')\nEOF"));
  denies(bash('sed -i s/a/b/ intent.md'));
  denies(bash('truncate -s 0 intent.md'));
  denies(bash('dd if=/dev/zero of=intent.md'));
  denies(bash('rm -rf tests'));
  denies(bash('ln -sf src/app.mjs intent.md'));
  denies(bash('git checkout -- intent.md'));
  allows(bash('echo x | tee -a src/log.txt'));
  allows(bash(`python3 -c "open('src/out.txt','w').write('x')"`));
});

test('ambiguous write targets are denied with an explanation', () => {
  denies(bash('echo x > $TARGET'));
  denies(bash('echo x > *.md'));
  denies(bash('echo $(cat intent.md) > src/copy.md'));
  denies(bash('cat "unterminated'));
  denies(bash('printf x > intent.md', 'relative/cwd'));
  allows(bash('echo x > src/name.txt'));
});

test('ordinary source edits and look-alike names are allowed', () => {
  allows(edit('Edit', '/workspace/src/app.mjs'));
  allows(edit('Write', '/workspace/src/new.mjs'));
  allows(edit('Write', 'src/intent.md'));
  allows(edit('Write', '/workspace/src/intent.md'));
  allows(edit('Write', '/workspace/src/tests/instructor/check.mjs'));
  allows(edit('Write', '/workspace/tests/instructor-notes.md'));
  allows(bash('printf x > src/intent.md'));
  allows(bash(`python3 -c "open('src/intent.md','w').write('x')"`));
  denies(edit('Write', '/workspace/intent.md'), 'the real target stays protected');
});

test('read-only commands are allowed', () => {
  allows(bash('cat intent.md'));
  allows(bash('head -n 5 intent.md && wc -l intent.md'));
  allows(bash('grep -rn approved intent.md tests/instructor'));
  allows(bash('cat tests/instructor/check.mjs | sort'));
  allows(bash('sed -n 1p intent.md'));
  allows(bash('ls -la; git status; git diff intent.md'));
  allows({tool_name: 'Read', tool_input: {file_path: '/workspace/intent.md'}, cwd: '/workspace'});
  denies(bash('cat intent.md > intent.md'), 'reading into the same file still writes it');
});

test('malformed events are denied with a reason instead of throwing', () => {
  for (const event of [null, undefined, {}, [], 'Bash', 42,
    {tool_name: 'Edit', tool_input: {}, cwd: '/workspace'},
    {tool_name: 'Write', tool_input: {file_path: 7}, cwd: '/workspace'},
    {tool_name: 'Edit', tool_input: {file_path: ''}, cwd: '/workspace'},
    {tool_name: 'Bash', tool_input: {}, cwd: '/workspace'},
    {tool_name: 'Bash', tool_input: {command: ['ls']}, cwd: '/workspace'},
    {tool_name: 'Bash', tool_input: null, cwd: '/workspace'},
    {tool_input: {command: 'ls'}, cwd: '/workspace'}]) {
    assert.doesNotThrow(() => decide(event));
    denies(event);
  }
});

test('deciding never changes the fixture files', {skip: !HAS_WORKSPACE && 'needs /workspace'}, () => {
  const files = ['/workspace/intent.md', '/workspace/tests/instructor/check.mjs', '/workspace/src/app.mjs'].filter(f => fs.existsSync(f));
  const before = files.map(f => fs.readFileSync(f, 'utf8'));
  denies(bash('printf changed > intent.md'));
  denies(edit('Write', '/workspace/src/shortcut'));
  allows(edit('Edit', '/workspace/src/app.mjs'));
  assert.deepEqual(files.map(f => fs.readFileSync(f, 'utf8')), before);
  assert.ok(fs.lstatSync('/workspace/src/shortcut').isSymbolicLink());
});
