#!/usr/bin/env node
'use strict';
/*
 * deob_unified.js
 * Luraph v15 deobfuscator: deob.js + src/{detect,driver,harness,vmmap,traceout,tidy,pyenv}.js
 * merged into ONE main function, deobfuscate(inputPath, args), that runs top to bottom.
 *
 * Put this file in the repo root (next to deob.js). It still needs:
 *   bin/luau, bin/luau-ast        (Luau runtime + AST dumper)
 *   runtime/*.luau, protocol.json (sandbox + protocol constants)
 *   core/                         (Python devirtualizer, run as an external process)
 *
 * Usage: node deob_unified.js <input.lua> [-o out.lua] [--no-devirt] [--debug] [--detect] ...
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');

// Python side of the pipeline (formerly src/devirt_bridge.py), embedded so src/ is not needed.
// deob_unified.js writes it to the work dir and runs it with PYTHONPATH=core.
const BRIDGE_PY = String.raw`import json
import os
import sys

# core/ is on sys.path via PYTHONPATH (set by deob_unified.js)

cmd = sys.argv[1]

if cmd == "pipeline":

    config_file = sys.argv[2]
    with open(config_file, "r", encoding="utf-8") as f:
        c = json.load(f)

    from obfuscators.base import Job
    from obfuscators.luraph_v15 import driver
    import harness

    class DummyArgs:
        DEFAULTS = {
            # --cfg KEY=VALUE list consumed by harness.user_cfg (the node cfg
            # extras already travel inside c["cfg"], so this stays empty)
            "cfg": [],
            "keep_harness": False, "no_hooks": False, "no_devirt": False,
            "max_runs": 1, "raw": None, "input_text": None, "port": None,
        }

        def __init__(self, d):
            for k, v in d.items():
                setattr(self, k, v)

        def __getattr__(self, k):
            # the python driver reads attrs the node CLI never passes
            return DummyArgs.DEFAULTS.get(k, False)

    args = DummyArgs(c["args"])
    job = Job(c["input"], c["source"], args, c["trace_path"], c["debug"], c["obfuscator"])
    job.source_path = c["source_path"]
    job.credit_header = lambda: ""

    runner = harness.Runner(job)
    runner.luau = c["luau_exe"]

    profiler = None
    prof_path = os.environ.get("DEOB_PROFILE")
    if prof_path:
        import cProfile
        profiler = cProfile.Profile()

    if profiler:
        profiler.enable()
    driver.lift(
        job,
        runner,
        c["patched"],
        c["cfg"],
        c.get("chunks", {}),
        c["run_text"],
        c["ppath"],
        c["dpath"],
        c.get("chunk_paths", []),
    )
    if profiler:
        profiler.disable()
        profiler.dump_stats(prof_path)
        sys.stderr.write("[*] cProfile stats written to %s\n" % prof_path)
    runner.finish()

    dpath = c["dpath"]
    if os.path.exists(dpath):
        with open(dpath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        clean = []
        skip_header = True
        for line in lines:
            stripped = line.strip()
            if skip_header and (
                stripped.startswith("-- Deobfuscated by") or
                stripped.startswith("-- Detected obfuscation") or
                stripped.startswith("-- Local names are inferred") or
                stripped.startswith("-- source:") or
                stripped.startswith("-- NOTE: reconstructed") or
                stripped.startswith("--       during the trace")
            ):
                continue
            if skip_header and stripped == "":
                continue
            skip_header = False
            clean.append(line)
        with open(dpath, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(clean)

    print(json.dumps({"success": True, "output": c["dpath"]}))

else:
    sys.exit(f"Unknown command: {cmd} (expected: pipeline)")
`;

async function deobfuscate(inputPath, args) {
  // ───────────────────────── 0. constants / tools ─────────────────────────
  const ROOT = __dirname;
  const BIN = path.join(ROOT, 'bin');
  const PROTO = JSON.parse(fs.readFileSync(path.join(ROOT, 'protocol.json'), 'utf8'));
  const SPIN_CHECKS = 24;
  const AST_TIMEOUT_MS = 120 * 1000;

  let MARK = '';                                   // per-run nonce for protocol lines
  const mark = (s) => '\x00' + MARK + s;
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const findBin = (name) => {
    const exe = process.platform === 'win32' ? name + '.exe' : name;
    let p = path.join(BIN, exe);
    if (!fs.existsSync(p)) {
      p = null;
      for (const d of (process.env.PATH || '').split(path.delimiter)) {
        const c = path.join(d, exe);
        if (fs.existsSync(c)) { p = c; break; }
      }
    }
    if (!p) throw new Error(`${name} not found: build it with build_luau.py or put it in ${BIN}`);
    if (process.platform !== 'win32') {
      try { fs.accessSync(p, fs.constants.X_OK); } catch { try { fs.chmodSync(p, 0o755); } catch {} }
    }
    return p;
  };
  const luauExe = findBin('luau');

  // Lua literal helpers used to build the sandbox harness
  const longString = (s) => {
    let level = 0;
    while (s.includes(']' + '='.repeat(level) + ']')) level++;
    const eq = '='.repeat(level);
    return '[' + eq + '[\n' + s + ']' + eq + ']';
  };
  const luaValue = (v) => {
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (Array.isArray(v)) return '{' + v.map(luaValue).join(', ') + '}';
    if (typeof v === 'string')
      return '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"';
    if (v === null || v === undefined) return 'nil';
    if (typeof v === 'object')
      return '{' + Object.entries(v).map(([k, val]) => `[${luaValue(k)}] = ${luaValue(val)}`).join(', ') + '}';
    return String(v);
  };
  const chunkKey = (src) => {
    const bytes = Buffer.from(src, 'latin1');
    let h = 0;
    for (const b of bytes) h = (h * PROTO.chunk_hash.multiplier + b) % PROTO.chunk_hash.modulus;
    return `${bytes.length}_${h}`;
  };

  // ───────────────────────── 1. read + detect obfuscator ─────────────────────────
  const absInput = path.resolve(inputPath);
  let source = fs.readFileSync(absInput, 'latin1');

  const LURAPH_HEADER = /This file was protected using Luraph Obfuscator v(\d+)(?:\.(\d+))?/;
  const VM_SHAPE = /\[\d+\]=(bit32|buffer|string|table|math)\.\w+/;
  const VM_START = /[\s\]]*return setmetatable\(\{/;
  const LUARMOR_SIGS = [
    /luarmor\.net|Luarmor/i, /\bluraph_runtime1\s*\(/, /GetTutorialState\(\s*"nil\s+nil\s+/,
    /getfenv\(\)\s*\[\s*tbl\w+\s*\]\s*=/, /writefile\(\s*"luarmor-error-log\.txt"/,
    /[a-z]{1,3}\d-roblox-auth\.luarmor\.net/, /ce_like_loadstring_fn/, /Kick\(\s*"\[Luarmor\]/,
  ];

  let obfuscator = 'generic', obfLabel = 'unknown obfuscator (behaviour trace only)', confidence = 0;
  if (args.plugin) {
    if (!['luraph_v15', 'luarmor_client'].includes(args.plugin))
      throw new Error(`Unknown obfuscator '${args.plugin}' (known: luraph_v15, luarmor_client)`);
    obfuscator = args.plugin; confidence = 1.0;
    obfLabel = args.plugin === 'luraph_v15' ? 'Luraph v15' : 'Luarmor whitelist client';
  } else {
    let cLuraph = 0;
    const hm = LURAPH_HEADER.exec(source.slice(0, 500));
    if (hm) cLuraph = hm[1] === '15' ? 1.0 : 0.3;
    else {
      const vm = VM_START.exec(source.slice(0, 65536));
      if (vm) {
        const at = vm.index + vm[0].length - 'return setmetatable({'.length;
        const head = source.slice(at, at + 200000);
        if (VM_SHAPE.test(head) || head.includes('LPH')) cLuraph = 0.8;
      }
    }
    const hits = LUARMOR_SIGS.filter(rx => rx.test(source)).length;
    const cLuarmor = hits >= 4 ? 1.0 : hits >= 3 ? 0.9 : hits >= 2 ? 0.7 : 0;
    if (cLuraph >= cLuarmor && cLuraph >= 0.5) { obfuscator = 'luraph_v15'; obfLabel = 'Luraph v15'; confidence = cLuraph; }
    else if (cLuarmor >= 0.5) { obfuscator = 'luarmor_client'; obfLabel = 'Luarmor whitelist client'; confidence = cLuarmor; }
  }

  if (args.detect) {
    console.log(`${path.basename(absInput)}\t${obfuscator}\t${confidence.toFixed(2)}\t${obfLabel}`);
    return null;
  }
  process.stderr.write(`[*] obfuscator: ${obfLabel} (detected, ${confidence.toFixed(2)})\n`);
  if (obfuscator === 'luarmor_client')
    throw new Error('Luarmor whitelist client detected: devirtualization/tracing not applicable.');

  // ───────────────────────── 2. work paths ─────────────────────────
  const outdir = path.join(path.dirname(absInput), 'output');
  fs.mkdirSync(outdir, { recursive: true });
  const tracename = path.basename(absInput).replace(/(\.luau?|\.txt)?$/, '.deobf.luau');
  const workdir = args.debug ? null : fs.mkdtempSync(path.join(os.tmpdir(), 'deobf_node_'));
  const tracePath = args.debug ? (args.output || path.join(outdir, tracename)) : path.join(workdir, tracename);
  const finalPath = args.output || path.join(outdir, path.basename(absInput));
  fs.mkdirSync(path.dirname(path.resolve(finalPath)), { recursive: true });

  const jobBase = tracePath.replace(/\.(deobf\.luau|luau)$/, '');
  const jobPath = (suffix) => jobBase + suffix;
  const jobWrite = (p, text, enc = 'utf8') => {
    fs.writeFileSync(p, text, { encoding: enc });
    if (args.debug) process.stderr.write(`[+] wrote ${p}\n`);
    return p;
  };
  const jobOutdir = path.dirname(path.resolve(tracePath));

  try {
    // header comment can lose its newline when pasted (e.g. Discord message.txt)
    let sourcePath = absInput;
    const hl = /\s*--[ \t]*This file was protected using Luraph Obfuscator v[\d.]+[ \t]*\[https?:\/\/lura\.ph\/?\]/.exec(source);
    if (hl) {
      const end = hl.index + hl[0].length;
      const nx = source[end];
      if (nx !== undefined && nx !== '\n' && nx !== '\r') {
        process.stderr.write('[*] header comment ran into the code: split it\n');
        source = source.slice(0, end) + '\n' + source.slice(end).replace(/^[ \t]+/, '');
        sourcePath = path.join(workdir || outdir, path.basename(absInput) + '.src.lua');
        fs.writeFileSync(sourcePath, source, 'latin1');
      }
    }

    const devirtOn = !args.noDevirt;

    // ───────────────────────── 3. AST instrumentation (vmmap) ─────────────────────────
    // instrument(src, file, tag): parse with luau-ast, find the VM dispatch loops and
    // closure makers, and splice capture hooks into the source. Recursive AST helpers
    // are nested here because they cannot be flattened into straight-line code.
    const instrument = (src, filePath, tag) => {
      // luau-ast dump
      let root;
      {
        let exe;
        try { exe = findBin('luau-ast'); } catch (e) { throw new SyntaxError(e.message); }
        let stdout;
        try {
          stdout = execFileSync(exe, [filePath], { encoding: 'latin1', maxBuffer: 256 * 1024 * 1024, timeout: AST_TIMEOUT_MS });
        } catch (e) {
          if (e.code === 'ENOENT') throw new SyntaxError('luau-ast binary is missing or not executable');
          if (e.code === 'ETIMEDOUT' || (e.message || '').includes('ETIMEDOUT'))
            throw new SyntaxError(`luau-ast timed out after ${AST_TIMEOUT_MS / 1000}s`);
          throw new SyntaxError('not valid Luau: ' + (e.stderr || e.message || '').trim().split('\n').slice(0, 3).join(' | '));
        }
        root = JSON.parse(stdout).root;
      }

      const loc = (node) => {
        const [a, b] = node.location.split(' - ');
        const [l1, c1] = a.split(',').map(Number);
        const [l2, c2] = b.split(',').map(Number);
        return [l1, c1, l2, c2];
      };
      const walkAst = (node, fn) => {
        if (!node || typeof node !== 'object') return;
        if (Array.isArray(node)) { node.forEach(v => walkAst(v, fn)); return; }
        fn(node);
        Object.values(node).forEach(v => walkAst(v, fn));
      };
      const localName = (e) => (e && e.type === 'AstExprLocal' ? e.local.name : null);
      const unwrap = (e) => { while (e && e.type === 'AstExprGroup') e = e.expr; return e; };
      const OPS = new Set(['CompareLt', 'CompareLe', 'CompareGt', 'CompareGe', 'CompareEq', 'CompareNe']);

      // dispatch loops: `while true do local op = ARR[PC]; if ...` or `repeat ... until false`
      const dispNodes = [];
      walkAst(root, n => {
        let body = null;
        if (n.type === 'AstStatWhile') {
          const c = n.condition;
          if (!c || c.type !== 'AstExprConstantBool' || !c.value) return;
          body = n.body.body;
        } else if (n.type === 'AstStatRepeat') {
          const c = n.condition;
          if (!c || c.type !== 'AstExprConstantBool' || c.value) return;
          body = n.body ? n.body.body : null;
        }
        if (!body || body.length < 2) return;
        for (const idx of [0, 1]) {
          if (idx >= body.length - 1) break;
          const st = body[idx];
          if (!['AstStatLocal', 'AstStatAssign'].includes(st.type)) continue;
          const vars = st.vars || [], vals = st.values || [];
          let matched = false;
          for (let k = 0; k < Math.min(vars.length, vals.length); k++) {
            const v = unwrap(vals[k]);
            if (!v || v.type !== 'AstExprIndexExpr') continue;
            const arr = localName(unwrap(v.expr)), pc = localName(unwrap(v.index));
            if (!arr || !pc) continue;
            const opname = st.type === 'AstStatLocal' ? vars[k].name : localName(vars[k]);
            if (!opname) continue;
            const nxtI = idx + 1;
            if (nxtI < body.length && body[nxtI].type === 'AstStatIf') { dispNodes.push(n); matched = true; break; }
            else if (nxtI + 1 < body.length && ['AstStatLocal', 'AstStatAssign'].includes(body[nxtI].type) &&
                     body[nxtI + 1].type === 'AstStatIf') {
              const st1 = body[nxtI];
              if ((st1.values || []).length === 1) {
                const v1 = unwrap(st1.values[0]);
                if (v1 && v1.type === 'AstExprBinary' && OPS.has(v1.op)) { dispNodes.push(n); matched = true; break; }
              }
            }
          }
          if (matched) break;
        }
      });

      // which maker parameter is the proto table / upvalue table
      const makerParams = (maker) => {
        const margs = maker.args || [];
        const visible = {};
        margs.forEach((a, i) => { visible[a.name] = i; });
        const counts = {}, kcounts = {}, acounts = {}, used = new Set();
        const paramLocs = new Set(margs.map(a => a.location));
        const aliases = {};
        const collectAliases = (n) => {
          if (!n || typeof n !== 'object') return;
          if (Array.isArray(n)) { n.forEach(collectAliases); return; }
          if (n.type === 'AstStatLocal' && Array.isArray(n.vars) && Array.isArray(n.values)) {
            for (let i = 0; i < Math.min(n.vars.length, n.values.length); i++) {
              const vr = n.vars[i], vl = n.values[i];
              if (vr?.type === 'AstLocal' && vl?.type === 'AstExprLocal') {
                const s = vl.local?.location;
                if (paramLocs.has(s) || aliases[s]) aliases[vr.location] = s;
              }
            }
          }
          Object.values(n).forEach(collectAliases);
        };
        collectAliases(maker.body);
        const resolveLoc = (l) => {
          let d = 0;
          while (d < 10 && !paramLocs.has(l) && aliases[l]) { l = aliases[l]; d++; }
          return l;
        };
        const visit = (n) => {
          if (!n || typeof n !== 'object') return;
          if (Array.isArray(n)) { n.forEach(visit); return; }
          if (n.type === 'AstExprLocal') used.add(n.local.location);
          if (n.type === 'AstExprIndexExpr' && n.expr?.type === 'AstExprLocal' &&
              n.index?.type === 'AstExprIndexExpr' && n.index?.expr?.type === 'AstExprLocal' &&
              n.index.expr.local.location === n.expr.local.location) {
            const k = n.expr.local.location;
            counts[k] = (counts[k] || 0) + 1;
            const ak = resolveLoc(k);
            if (ak !== k) acounts[ak] = (acounts[ak] || 0) + 1;
          }
          if (n.type === 'AstExprIndexExpr' && n.expr?.type === 'AstExprLocal' && n.index?.type === 'AstExprConstantNumber') {
            const k = n.expr.local.location;
            kcounts[k] = (kcounts[k] || 0) + 1;
            const ak = resolveLoc(k);
            if (ak !== k) kcounts[ak] = (kcounts[ak] || 0) + 1;
          }
          Object.values(n).forEach(visit);
        };
        visit(maker.body);
        const cands = Object.values(visible).filter(i => i > 0);
        let pi = cands.length
          ? cands.reduce((best, i) => {
              const bc = counts[margs[best]?.location] || 0;
              const ic = counts[margs[i]?.location] || 0;
              return ic > bc ? i : (ic === bc && i === 1 ? i : best);
            }, cands[0])
          : 1;
        if (!counts[margs[pi]?.location]) {
          const ac = cands.filter(i => acounts[margs[i]?.location]);
          const kc = cands.filter(i => kcounts[margs[i]?.location]);
          if (ac.length) pi = ac.reduce((b, i) => (acounts[margs[i].location] > acounts[margs[b].location] ? i : b), ac[0]);
          else if (kc.length) pi = kc.reduce((b, i) => (kcounts[margs[i].location] > kcounts[margs[b].location] ? i : b), kc[0]);
          else pi = 1;
        }
        const others = Object.values(visible).filter(i => i !== 0 && i !== pi && used.has(margs[i]?.location)).sort();
        const ui = others.length ? others[0] : (pi + 1 >= margs.length && pi > 1 ? pi - 1 : pi + 1);
        return [pi, ui];
      };

      const vmStackIdx = (stack) => {
        if (stack.length >= 2) {
          const f1 = stack[stack.length - 1], f2 = stack[stack.length - 2];
          if (f1.vararg && (!f1.args || f1.args.length === 0) && f2.vararg && (!f2.args || f2.args.length === 0))
            return stack.length - 2;
        }
        return stack.length - 1;
      };

      const curried3Of = (stack, vmIdx) => {
        if (vmIdx < 2) return null;
        const f3 = stack[vmIdx - 2], f2 = stack[vmIdx - 1], f1 = stack[vmIdx];
        const f3b = f3.body && f3.body.body;
        const retStmt = f3b && f3b[f3b.length - 1];
        if ((f3.args || []).length < 5 || !retStmt || retStmt.type !== 'AstStatReturn' || !retStmt.list || retStmt.list.length !== 1)
          return null;
        if (retStmt.list[0] === f2) return { f3, f2, f1, retStmt, kind: 'anon' };
        const uName = localName(retStmt.list[0]);
        const f2b = f2.body && f2.body.body;
        const f2Ret = f2b && f2b[f2b.length - 1];
        const zName = f2Ret && f2Ret.type === 'AstStatReturn' && f2Ret.list && f2Ret.list.length === 1 ? localName(f2Ret.list[0]) : null;
        if (uName && zName) return { f3, f2, f1, retStmt, f2Ret, uName, zName, kind: 'named' };
        return null;
      };

      const declsIn = (fn) => {
        const keys = {};
        const visit = (n) => {
          if (!n || typeof n !== 'object') return;
          if (Array.isArray(n)) { n.forEach(visit); return; }
          const t = n.type;
          if (t === 'AstExprFunction' && n !== fn) return;
          if (t === 'AstStatLocal') (n.vars || []).forEach(v => { keys[v.location] = v.name; });
          else if (t === 'AstStatLocalFunction') keys[n.name.location] = n.name.name;
          else if (t === 'AstStatFor') keys[n.var.location] = n.var.name;
          else if (t === 'AstStatForIn') (n.vars || []).forEach(v => { keys[v.location] = v.name; });
          Object.values(n).forEach(visit);
        };
        (fn.args || []).forEach(a => { keys[a.location] = a.name; });
        visit(fn.body);
        return keys;
      };
      const locStart = (key) => String(key).split(' - ')[0].split(',').map(Number);

      const freeNames = (fn) => {
        const own = new Set(Object.keys(declsIn(fn)));
        const names = new Set();
        const visit = (n) => {
          if (!n || typeof n !== 'object') return;
          if (Array.isArray(n)) { n.forEach(visit); return; }
          if (n.type === 'AstExprLocal' && n.local && !own.has(n.local.location)) names.add(n.local.name);
          Object.values(n).forEach(visit);
        };
        visit(fn.body);
        return [...names].sort();
      };

      const captures = (info) => {
        const makerDecls = declsIn(info.maker);
        const chainDecls = {};
        if (info.chain && info.chain.length) {
          const mk = locStart(info.maker.location);
          info.chain.forEach(fn => {
            Object.entries(declsIn(fn)).forEach(([k, nm]) => {
              const [l1, c1] = locStart(k);
              if (l1 < mk[0] || (l1 === mk[0] && c1 <= mk[1])) (chainDecls[nm] = chainDecls[nm] || []).push(k);
            });
          });
        }
        const usedMaker = {}, usedChain = {};
        const visit = (n) => {
          if (!n || typeof n !== 'object') return;
          if (Array.isArray(n)) { n.forEach(visit); return; }
          if (n.type === 'AstExprLocal') {
            const k = n.local.location, nm = n.local.name;
            if (makerDecls[k]) usedMaker[k] = nm;
            else if (chainDecls[nm] && chainDecls[nm].includes(k)) usedChain[k] = nm;
          }
          Object.values(n).forEach(visit);
        };
        visit(info.vm);
        const single = (members, declsByName) => {
          const refKeys = {};
          Object.entries(members).forEach(([k, nm]) => { (refKeys[nm] = refKeys[nm] || []).push(k); });
          return new Set(Object.keys(refKeys).filter(nm => refKeys[nm].length === 1 && (declsByName[nm] || []).length === 1));
        };
        const makerByName = {};
        Object.entries(makerDecls).forEach(([k, nm]) => { (makerByName[nm] = makerByName[nm] || []).push(k); });
        const caps = single(usedMaker, makerByName);
        single(usedChain, chainDecls).forEach(nm => { if (!(nm in makerDecls)) caps.add(nm); });
        return [...caps].sort();
      };

      // walk 1: entry hooks (start of each VM closure body)
      const entries = new Map();
      (function walkEntries(n, stack) {
        if (!n || typeof n !== 'object') return;
        if (Array.isArray(n)) { n.forEach(v => walkEntries(v, stack)); return; }
        if (n.type === 'AstExprFunction') stack = [...stack, n];
        if (dispNodes.includes(n)) {
          const vmIdx = vmStackIdx(stack);
          const inner = stack[vmIdx] && stack[vmIdx].vararg && (!stack[vmIdx].args || stack[vmIdx].args.length === 0)
            ? stack[vmIdx]
            : [...stack].reverse().find(f => f.vararg && (!f.args || f.args.length === 0));
          const outer = [...stack].reverse().find(f => f.args && f.args.length >= 2);
          if (inner && outer) {
            const first = inner.body.body[0];
            if (first) {
              const [l1, c1] = loc(first);
              const [pi] = makerParams(outer);
              let name = outer.args[pi].name;
              if (curried3Of(stack, vmIdx)) name = '__pv';
              entries.set(`${l1},${c1}`, [l1, c1, name]);
            }
          }
        }
        Object.values(n).forEach(v => walkEntries(v, stack));
      })(root, []);

      // walk 2: maker hooks (where a VM closure is created)
      const makers = new Map();
      (function walkMakers(n, stack, stmts) {
        if (!n || typeof n !== 'object') return;
        if (Array.isArray(n)) { n.forEach(v => walkMakers(v, stack, stmts)); return; }
        const t = n.type;
        if (t === 'AstExprFunction') stack = [...stack, n];
        if (t && t.startsWith('AstStat')) stmts = [...stmts, [n, stack.length]];
        if (dispNodes.includes(n)) {
          let oi = -1;
          for (let i = stack.length - 1; i >= 0; i--) if ((stack[i].args || []).length >= 2) { oi = i; break; }
          let registered = false;
          if (oi >= 0 && oi + 1 < stack.length) {
            const clo = stack[oi + 1];
            const makerStmts = stmts.filter(([, d]) => d === oi + 1).map(([s]) => s);
            const st = makerStmts[makerStmts.length - 1];
            if (st && st.type === 'AstStatAssign') {
              (st.vars || []).forEach((v, idx) => {
                const e = (st.values || [])[idx];
                if (e === clo && localName(v)) {
                  const [, , l2, c2] = loc(st);
                  const key = `${l2},${c2}`;
                  if (!makers.has(key)) {
                    const [pi, ui] = makerParams(stack[oi]);
                    makers.set(key, {
                      at: [l2, c2], var: localName(v), proto: stack[oi].args[pi].name,
                      proto_index: pi, upvals_index: ui, pf_key: stack[oi].args[pi].name,
                      maker: stack[oi], vm: clo, stmt: st, chain: stack.slice(0, oi),
                    });
                  }
                  registered = true;
                }
              });
            }
          }
          if (!registered) {      // dispatch-local proto fallback
            const vmIdx = vmStackIdx(stack);
            const clo = stack[vmIdx];
            if (clo && clo.vararg && (!clo.args || clo.args.length === 0)) {
              const bbody = clo.body && clo.body.body;
              if (bbody && bbody.length >= 2 && bbody[0].type === 'AstStatLocal' && bbody[0].vars && bbody[0].vars[0]) {
                let targetIdx = 0, pv = bbody[0].vars[0].name;
                const shadowed = new Set();
                for (let si = 0; si < bbody.length - 1; si++) {
                  const st = bbody[si];
                  if (st.type !== 'AstStatLocal') break;
                  const vals = st.values || [];
                  let foundCall = false;
                  for (let vi = 0; vi < vals.length; vi++) {
                    if (vals[vi] && vals[vi].type === 'AstExprCall' && st.vars && st.vars[vi]) {
                      targetIdx = si; pv = st.vars[vi].name; foundCall = true; break;
                    }
                  }
                  if (foundCall) break;
                }
                for (let si = 0; si <= targetIdx; si++) (bbody[si].vars || []).forEach(v2 => shadowed.add(v2.name));
                const first = bbody[targetIdx], second = bbody[targetIdx + 1];
                const [l2, c2] = loc(second);
                const key = `v3:${l2},${c2}`;
                if (!makers.has(key)) {
                  makers.set(key, {
                    at: [l2, c2], var: pv, proto: pv, mode: 'dispatch_local',
                    pf_key: JSON.stringify(`disp@${l2},${c2}`),
                    maker: vmIdx >= 1 ? stack[vmIdx - 1] : null, vm: clo, stmt: first,
                    captures: freeNames(clo).filter(nm => !shadowed.has(nm)),
                    curried3: curried3Of(stack, vmIdx),
                    chain: vmIdx >= 1 ? stack.slice(0, vmIdx - 1) : [],
                  });
                }
              }
            }
          }
        }
        Object.values(n).forEach(v => walkMakers(v, stack, stmts));
      })(root, [], []);
      const makerList = [...makers.values()];
      makerList.forEach(info => { if (info.mode !== 'dispatch_local') info.captures = captures(info); });

      // build the edit list and splice it into the source (back to front)
      const lines = src.split('\n');
      const edits = [];
      for (const [l1, c1, name] of entries.values()) {
        const k = `(${name} or __PID)`;
        edits.push([l1, c1,
          `if not __PID[${k}] then __PID.n=__PID.n+1;__PID[${k}]=__PID.n;end;` +
          `if __PARG1 and not __PARG1[__PID[${k}]] and type((...))=="number" then __PARG1[__PID[${k}]]=(...) end;` +
          `__ENT.n=__ENT.n+1;__ENT[__ENT.n%64]=__PID[${k}];__PLAST[__PID[${k}]]=__ENT.n;` +
          `if __SKIPP[__PID[${k}]] then return end;`]);
      }
      for (const info of makerList) {
        const [l2, c2] = info.at;
        if (info.curried3) {
          const { f3, f2, f1, retStmt, f2Ret, uName, zName, kind } = info.curried3;
          const [f3l, f3c] = loc(f3.body.body[0]);
          const f3Cap = [...new Set((f3.args || []).map(a => a.name).filter(nm => nm && nm !== '...'))].map(nm => `${nm}=${nm}`).join(',');
          edits.push([f3l, f3c,
            `local __pv={${f3Cap}};if __PA and __PA.n<8192 then __PA.n=__PA.n+1;__PA[__pv]={__seq=__PA.n,__maker="${tag}@${l2},${c2}",${f3Cap}} end;`]);
          if (kind === 'named') {
            const [r1l, r1c] = loc(retStmt), [r2l, r2c] = loc(f2Ret);
            edits.push([r1l, r1c, `__PF[${uName}]=__pv;__PK[__pv]=${uName};`]);
            edits.push([r2l, r2c, `__PF[${zName}]=__pv;__PK[__pv]=${zName};`]);
          } else {
            const [a1, b1, a2, b2] = loc(f2);
            edits.push([a1, b1, `(function(__mk)__PF[__mk]=__pv;__PK[__pv]=__mk;return __mk end)(`]);
            edits.push([a2, b2, `)`]);
            if (f1) {
              const [c1l, c1c, c2l, c2c] = loc(f1);
              edits.push([c1l, c1c, `(function(__fn)__PF[__fn]=__pv;return __fn end)(`]);
              edits.push([c2l, c2c, `)`]);
            }
          }
          continue;
        }
        const pv = info.proto, v = info.var, pfKey = info.pf_key || pv;
        const cap = info.captures.map(nm => `__PA[${pv}].${nm}=${nm};`).join('');
        const palimit = info.mode === 'dispatch_local' ? 64 : 8192;
        let code = ` __PF[${v}]=${pfKey} ` +
          `if __PA and __PA.n<${palimit} and ${pv}~=nil and not __PA[${pv}] then __PA[${pv}]={};__PA.n=__PA.n+1;__PA[${pv}].__seq=__PA.n;` +
          `__PA[${pv}].__maker="${tag}@${l2},${c2}";__PK[${pfKey}]=${v};${cap} end `;
        if (info.mode === 'dispatch_local') code += ' ';
        edits.push([l2, c2, code]);
      }
      edits.sort((a, b) => (b[0] !== a[0] ? b[0] - a[0] : b[1] - a[1]));
      for (const [l, c, code] of edits) lines[l] = lines[l].slice(0, c) + code + lines[l].slice(c);
      return lines.join('\n');
    };

    // loop-spin guard: inject a counter into the VM dispatch loop
    const spinPatch = (src) => {
      const INJ = '__SPIN.n=__SPIN.n+1;if __SPIN.n>=__SPIN.step then __SPIN.f()end;';
      const id = '[A-Za-z_][A-Za-z0-9_]*';
      const tail = `(?:${id}\\[\\d+\\]=${id};\\s*)?(?:local )?${id}(?:,${id})*=(?:${id},)?\\(?${id}\\[${id}\\]\\)?;?(?=\\s*(?:if|local)\\b)`;
      const add = (m) => (m.endsWith(';') ? m : m + ';') + INJ;
      return src.replace(new RegExp('while true do ' + tail, 'g'), add).replace(new RegExp('repeat ' + tail, 'g'), add);
    };

    let patched;
    try {
      patched = args.noHooks ? source : instrument(source, sourcePath, chunkKey(source));
    } catch (e) {
      process.stderr.write(`[!] AST parse failed: ${e.message}\n`);
      throw e;
    }
    patched = spinPatch(patched);

    // ───────────────────────── 4. Path2D replay cache ─────────────────────────
    const P2D_CACHE = new Map();
    const cachePath = absInput.replace(/\.(luau?|txt)?$/, '.path2d');
    if (fs.existsSync(cachePath)) {
      for (const line of fs.readFileSync(cachePath, 'utf8').split('\n')) {
        const tab = line.indexOf('\t');
        if (tab > 0) P2D_CACHE.set(line.slice(0, tab), line.slice(tab + 1));
      }
      process.stderr.write(`[*] replaying ${P2D_CACHE.size} recorded Path2D results from ${cachePath}\n`);
    }

    // ───────────────────────── 5. trace loop (sandboxed Luau runs) ─────────────────────────
    const SHIELD_STDLIB = `{
        string = string, math = math, table = table, os = os, debug = debug,
        coroutine = coroutine, bit32 = bit32, buffer = buffer, utf8 = utf8, vector = vector,
        type = type, typeof = typeof, pairs = pairs, ipairs = ipairs, next = next,
        select = select, rawget = rawget, rawset = rawset, rawequal = rawequal,
        rawlen = rawlen, setmetatable = setmetatable, getmetatable = getmetatable,
        tostring = tostring, tonumber = tonumber, error = error, assert = assert, print = print,
        pcall = pcall, xpcall = xpcall, unpack = table.unpack, newproxy = newproxy,
}`;
    const rd = (f, enc) => (fs.existsSync(f) ? fs.readFileSync(f, enc).replace('--!nocheck', '') : '');
    const runtimeDir = path.join(ROOT, 'runtime');
    const PROTO_LINE_RE = /local PROTO = \{[^}]*\}/;
    const ch = PROTO.chunk_hash;
    const protoLua = `local PROTO = { hash_mult = ${ch.multiplier}, hash_mod = ${ch.modulus}, hash_stride = ${ch.stride}, chunk_min = ${ch.min_len} }`;
    let runtime = rd(path.join(runtimeDir, 'envlog.luau'), 'utf8');
    if (!PROTO_LINE_RE.test(runtime)) throw new Error('runtime/envlog.luau lost its `local PROTO = {...}` line (see protocol.json)');
    runtime = runtime.replace(PROTO_LINE_RE, protoLua);
    const udata = rd(path.join(runtimeDir, 'unicode_data.luau'), 'ascii');
    const rdata = rd(path.join(runtimeDir, 'roblox_api.luau'), 'ascii');
    const dtypes = rd(path.join(runtimeDir, 'datatypes.luau'), 'utf8');

    const skip = [];
    const chunks = {};
    const rawChunks = {};
    const hpath = tracePath + '.harness.luau';
    let body = null, trapped = null, cfg = null, lastRaw = '';

    for (let attempt = 1; attempt <= args.maxRuns; attempt++) {
      cfg = { time_budget: args.budget, dump_strings: args.strings, executor: args.executor, skip_protos: skip, devirt: devirtOn };
      if (args.inputText) cfg.input_text = args.inputText;
      if (args.preludeFile) cfg.prelude = fs.readFileSync(args.preludeFile, 'latin1');
      if (args.noFold) cfg.fold = false;
      cfg.spin = SPIN_CHECKS;
      if (args.cfgJson) Object.assign(cfg, args.cfgJson);

      process.stderr.write(`[*] tracing ${absInput} (run ${attempt})...\n`);

      // build harness: shielded runtime + analyzed script + config
      const runCfg = Object.assign({ heartbeat: PROTO.heartbeat_seconds }, cfg);
      const cfgLua = '{' + Object.entries(runCfg).map(([k, v]) => `${k} = ${luaValue(v)}`).join(', ') + '}';
      const p2dLua = '{' + [...P2D_CACHE.entries()].map(([k, v]) => `[${luaValue(k)}] = ${luaValue(v)},\n`).join('') + '}';
      const chunksLua = '{' + Object.entries(chunks).map(([k, v]) => `[${luaValue(k)}] = ${longString(v)},\n`).join('') + '}';
      MARK = crypto.randomBytes(PROTO.nonce_hex_bytes).toString('hex');
      const harnessText =
        'local __STDLIB = ' + SHIELD_STDLIB + '\n' +
        'local __SHIELD = setmetatable({}, { __index = __STDLIB })\n' +
        'local __UNICODE = (function()\n' + udata + '\nend)()\n' +
        'local __ROBLOX = (function()\n' + rdata + '\nend)()\n' +
        '__ROBLOX.datatypes = (function()\n' + dtypes + '\nend)()\n' +
        'local __RAW = { getfenv = getfenv, setfenv = setfenv, loadstring = loadstring }\n' +
        'local __RUN = function(__MARK, __SOURCE, __CONFIG, __P2D, __CHUNKS, __UNICODE, __ROBLOX, __RAW)\n' +
        runtime + '\nend\n' +
        'setfenv(__RUN, __SHIELD)\n' +
        'return __RUN(' + luaValue(MARK) + ', ' + longString(patched) + ', ' + cfgLua + ',\n' +
        '  ' + p2dLua + ', ' + chunksLua + ', __UNICODE, __ROBLOX, __RAW)\n';
      fs.writeFileSync(hpath, harnessText, 'latin1');

      // run luau with timeout + stall watchdog
      const { stdoutText, errText } = await new Promise((resolve) => {
        const proc = spawn(luauExe, [hpath], { stdio: ['ignore', 'pipe', 'pipe'] });
        const outBufs = [], errBufs = [];
        let lastOutput = Date.now(), done = false;
        const finish = () => {
          if (done) return;
          done = true;
          clearInterval(watchdog);
          resolve({ stdoutText: Buffer.concat(outBufs).toString('utf8'), errText: Buffer.concat(errBufs).toString('utf8') });
        };
        proc.stdout.on('data', b => { outBufs.push(b); lastOutput = Date.now(); });
        proc.stderr.on('data', b => { errBufs.push(b); lastOutput = Date.now(); });
        proc.on('close', finish);
        proc.on('error', e => { errBufs.push(Buffer.from(e.message)); finish(); });
        const start = Date.now();
        const watchdog = setInterval(() => {
          const now = Date.now();
          if (now - start > args.timeout * 1000 || now - lastOutput > PROTO.stall_seconds * 1000) {
            proc.kill('SIGKILL');
            errBufs.push(Buffer.from(`\ntimed out after ${Math.round((now - start) / 1000)}s`));
            finish();
          }
        }, 200);
      });
      if (!args.keepHarness && fs.existsSync(hpath)) { try { fs.unlinkSync(hpath); } catch {} }

      const stdout = stdoutText.replace(new RegExp(mark('HB') + '\\r?\\n {16384}\\r?\\n', 'g'), '').replace(/\r\n/g, '\n');
      lastRaw = stdout + errText;
      const m = new RegExp(mark('ENVLOG-BEGIN') + '\\n([\\s\\S]*?)' + mark('ENVLOG-END')).exec(stdout);
      if (!m) throw new Error((stdout.slice(-3000) + '\n' + errText.slice(-3000)) || 'Trace failed without output');
      body = m[1];
      for (const hp of [hpath, hpath.replace(/\\/g, '/')]) {
        if (body.includes(hp + ':')) body = body.replace(new RegExp(esc(hp) + ':\\d+: ', 'g'), '');
      }

      // Path2D answers computed by the offline model
      const p2d = [];
      body = body.replace(new RegExp(mark('P2D ') + '([^\\t\\n]+)\\t([^\\n]*)\\n', 'g'), (_, k, v) => { p2d.push([k, v]); return ''; });
      const nmodel = p2d.filter(([, v]) => v.endsWith('\tmodel')).length;
      if (nmodel) process.stderr.write(`[*] ${nmodel} Path2D answers computed by the offline engine model\n`);

      // loadstring'd VM chunks: collect, instrument, re-run
      const found = [];
      body = body.replace(new RegExp(mark('CHUNK ') + '(\\S+)\\n([0-9a-f]*)\\n', 'g'), (_, k, hx) => {
        found.push([k, Buffer.from(hx, 'hex').toString('latin1')]);
        return '';
      });
      let added = 0;
      for (const [key, src] of found) {
        if (chunks[key]) continue;
        rawChunks[key] = src;
        const cp = path.join(jobOutdir, `_chunk_${chunkKey(src)}.luau`);
        fs.writeFileSync(cp, src, 'latin1');
        try { chunks[key] = instrument(src, cp, key); }
        catch (e) { process.stderr.write(`[!] could not instrument chunk (${e.message})\n`); chunks[key] = src; }
        finally { try { fs.unlinkSync(cp); } catch {} }
        chunks[key] = spinPatch(chunks[key]);
        added++;
      }
      if (added > 0) {
        process.stderr.write(`[*] script loadstring'd ${added} new VM chunk(s); instrumenting and re-running\n`);
        continue;
      }

      // anti-tamper trap handling
      const stmtCount = (b) => { const mm = /-- (\d+) statements recorded/.exec(b); return mm ? parseInt(mm[1], 10) : 0; };
      const trig = new RegExp(mark('TRIGGER ') + '(\\d+)').exec(body);
      if (trapped !== null && stmtCount(body) < stmtCount(trapped[0])) {
        process.stderr.write(`[*] disabling function #${skip[skip.length - 1]} made script stop earlier: keeping run ${attempt - 1}\n`);
        body = trapped[0];
        skip.pop();
        break;
      }
      if (!trig) break;
      trapped = [body, lastRaw];
      const pid = parseInt(trig[1], 10);
      if (skip.includes(pid)) {
        process.stderr.write(`[!] anti-tamper trigger ${pid} fired again; giving up on reruns\n`);
        break;
      }
      process.stderr.write(`[*] anti-tamper trap reached through function #${pid}; disabling it and re-running\n`);
      skip.push(pid);
    }

    // ───────────────────────── 6. post-process the trace ─────────────────────────
    // normalized trace text (kept for the Python side)
    const runText = body
      .replace(/\x00[0-9a-f]{8,32}CHUNK \S+\n[0-9a-f]*\n/g, '')
      .replace(/\x00[0-9a-f]{8,32}(PROTOS|FORCE|P2D|TRIGGER)[^\n]*\n?/g, '')
      .replace(/(?<=[ \t])(?=\S)(?:[A-Za-z]:)?[^:\n]*?\.luau:/g, 'harness:')
      .replace(/harness:\d+: /g, '')
      .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
      .replace(/\d+(?:\.\d+)?(?:e[-+]?\d+)?/g, '0');

    if (body.includes(mark('P2DMISS'))) {
      process.stderr.write(`[!] this script derives keys from a Path2D call the offline model does not cover\n    (run it once with --studio if needed; writes ${cachePath})\n`);
      body = body.replace(new RegExp(mark('P2DMISS') + '\\n', 'g'), '');
    }
    body = body.replace(new RegExp(mark('TRIGGER ') + '\\d+\\n?', 'g'), '');

    // pull out single-line protocol records
    const rec = {};
    for (const name of ['PROTOS', 'FORCE', 'UNSCRAMBLED']) {
      const mm = new RegExp(mark(name + ' ') + '([^\\n]*)\\n').exec(body);
      rec[name] = mm ? mm[1] : null;
      if (mm) body = body.slice(0, mm.index) + body.slice(mm.index + mm[0].length);
    }
    const protosJson = rec.PROTOS;
    if (rec.FORCE && devirtOn) process.stderr.write(`[*] constants decoded on request: ${rec.FORCE}\n`);
    if (rec.UNSCRAMBLED && devirtOn) process.stderr.write(`[*] ${rec.UNSCRAMBLED} function(s) scrambled by LPH_CRASH(): dumped as created\n`);

    // dumped strings
    let strings = null;
    {
      const sm = mark('ENVLOG-STRINGS\n');
      const idx = body.indexOf(sm);
      if (idx !== -1) { strings = body.slice(idx + sm.length); body = body.slice(0, idx); }
    }

    const notes = skip.length ? [`anti-tamper trap functions disabled: ${skip.map(p => '#' + p).join(', ')}`] : [];
    const text = notes.map(n => `-- ${n}\n`).join('') + body;

    // tidy: strip markers, strip envlog annotations, optionally strip preamble
    const tidyText = () => {
      let res = text.replace(/--@\S*\n?/g, '');
      const clean = [];
      let inList = false;
      for (const line of res.split('\n')) {
        const t = line.trim();
        if (t.startsWith('-- URLs requested:') || t.startsWith('-- remotes fired/invoked:') ||
            t.startsWith('-- non-standard globals touched:') || t.startsWith('-- anti-tamper trap')) { inList = true; continue; }
        if (inList) { if (t.startsWith('--   ') || t === '--') continue; inList = false; }
        if (t.startsWith('-- [envlog]') || t.startsWith('-- isfolder(') || t.startsWith('-- isfile(') ||
            t.startsWith('-- identifyexecutor(') || t.startsWith('-- condition:') || t.startsWith('-- loadstring() of') ||
            t.startsWith('-- run status:') || /^--\s*\d+\s+statements recorded/.test(t)) continue;
        clean.push(line);
      }
      res = clean.join('\n').replace(/^\n+/, '');
      if (!args.keepPreamble) {
        const ls = res.split('\n');
        let cut = 0;
        for (let i = 0; i < Math.min(ls.length, 120); i++)
          if (ls[i].includes('Path2D:GetTangentOnCurveArcLength') || ls[i].includes('ScreenGui:Destroy()')) cut = i + 1;
        if (cut > 0) res = ls.slice(cut).join('\n').replace(/^\n+/, '');
      }
      return res;
    };

    if (!devirtOn && !args.debug) jobWrite(tracePath, tidyText());
    if (strings) jobWrite(jobPath('.strings.txt'), strings);

    // ───────────────────────── 7. devirtualization (Python core, external) ─────────────────────────
    const dpath = jobPath('.devirt.luau');
    if (protosJson) {
      const ppath = jobPath('.protos.json');
      if (protosJson.startsWith('error:')) {
        process.stderr.write(`[!] proto capture failed: ${protosJson}\n`);
      } else {
        jobWrite(ppath, protosJson);
        if (devirtOn) {
          const chunkPaths = Object.entries(rawChunks).map(([k, src]) => jobWrite(jobPath(`.chunk_${k}.luau`), src, 'latin1'));
          const cfgPath = jobPath('.cfg.json');
          fs.writeFileSync(cfgPath, JSON.stringify({
            input: absInput, source, source_path: sourcePath, trace_path: tracePath, debug: !!args.debug,
            obfuscator: obfLabel, luau_exe: luauExe, patched, cfg, chunks, run_text: runText,
            ppath, dpath, chunk_paths: chunkPaths,
            args: {
              budget: args.budget, timeout: args.timeout, devirt_rounds: args.devirtRounds || 200,
              studio: false, no_fold: args.noFold || false, strings: args.strings || false,
              executor: args.executor || 'Wave',
            },
          }), 'utf8');

          // python binary lookup
          let pythonBin = process.env.PYTHON_BIN || null;
          if (!pythonBin) {
            for (const cmd of (process.platform === 'win32' ? ['python', 'py', 'python3'] : ['python3', 'python'])) {
              try { execFileSync(cmd, ['--version'], { stdio: 'ignore' }); pythonBin = cmd; break; } catch {}
            }
          }
          if (!pythonBin) throw new Error('Python not found. Install Python 3.10+ or set PYTHON_BIN.');
          const bridgePath = jobPath('.bridge.py');
          fs.writeFileSync(bridgePath, BRIDGE_PY, 'utf8');
          try {
            execFileSync(pythonBin, [bridgePath, 'pipeline', cfgPath], {
              env: Object.assign({}, process.env, { PYTHONPATH: path.join(ROOT, 'core') }),
              stdio: 'inherit',
            });
          } finally { try { fs.unlinkSync(cfgPath); } catch {} try { fs.unlinkSync(bridgePath); } catch {} }
        }
      }
    }
    process.stderr.write('[*] ' + ((body || '').split('\n')[0] || '').replace(/^--\s*/, '') + '\n');

    // ───────────────────────── 8. choose result ─────────────────────────
    let result;
    if (devirtOn && fs.existsSync(dpath)) {
      const lifted = fs.readFileSync(dpath, 'utf8');
      const nilCalls = (lifted.match(/\(nil\)\(/g) || []).length;
      const nLines = lifted.split('\n').length;
      if (nilCalls < 50 || nilCalls * 100 < nLines) {
        result = dpath;
      } else {
        process.stderr.write(`[!] the devirtualized output is broken (${nilCalls} calls of nil); writing behaviour trace instead\n`);
        if (!args.debug) { try { fs.unlinkSync(dpath); } catch {} }
        jobWrite(tracePath, tidyText());
        result = tracePath;
      }
    } else {
      if (devirtOn) {
        process.stderr.write('[!] devirtualization produced no output; writing behaviour trace\n');
        if (!fs.existsSync(tracePath)) jobWrite(tracePath, tidyText());
      }
      result = tracePath;
    }

    // ───────────────────────── 9. final file ─────────────────────────
    if (result && fs.existsSync(result)) {
      let content = fs.readFileSync(result, 'utf8');
      content = content.replace(/^(\s*--(?:[ \t]*(?:Deobfuscated by|Detected obfuscation|Local names are inferred|source:|NOTE: reconstructed|during the trace)[^\n]*\n?|\s*\n))+/, '');
      fs.writeFileSync(finalPath, content, 'utf8');
      process.stderr.write(`[+] result: ${finalPath}\n`);
      return finalPath;
    }
    process.stderr.write(`[!] no result for ${path.basename(absInput)}\n`);
    return null;
  } finally {
    if (workdir && fs.existsSync(workdir)) { try { fs.rmSync(workdir, { recursive: true, force: true }); } catch {} }
  }
}

// ───────────────────────── CLI ─────────────────────────
if (require.main === module) (async () => {
  const argv = process.argv.slice(2);
  const args = {
    inputs: [], output: null, detect: false, plugin: null, noDevirt: false, noHooks: false, noFold: false,
    debug: false, strings: false, keepHarness: false, keepPreamble: false, timeout: 90, budget: 30,
    maxRuns: 12, devirtRounds: 200, executor: 'Wave', inputText: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--detect') args.detect = true;
    else if (a === '--plugin') args.plugin = argv[++i];
    else if (a === '--no-devirt') args.noDevirt = true;
    else if (a === '--no-hooks') args.noHooks = true;
    else if (a === '--no-fold') args.noFold = true;
    else if (a === '--debug') args.debug = true;
    else if (a === '--strings') args.strings = true;
    else if (a === '--keep-harness') args.keepHarness = true;
    else if (a === '--keep-preamble') args.keepPreamble = true;
    else if (a === '-o' || a === '--output') args.output = argv[++i];
    else if (a === '--timeout') args.timeout = parseInt(argv[++i], 10);
    else if (a === '--prelude-file') args.preludeFile = argv[++i];
    else if (a === '--budget') args.budget = parseInt(argv[++i], 10);
    else if (a === '--max-runs') args.maxRuns = parseInt(argv[++i], 10);
    else if (a === '--devirt-rounds') args.devirtRounds = parseInt(argv[++i], 10);
    else if (a === '--executor') args.executor = argv[++i];
    else if (a === '--input-text') args.inputText = argv[++i];
    else if (a === '--cfg-json') {
      let spec = argv[++i];
      if (spec.startsWith('@')) spec = fs.readFileSync(spec.slice(1), 'utf8');
      args.cfgJson = JSON.parse(spec);
    } else if (!a.startsWith('-')) args.inputs.push(a);
  }
  if (args.inputs.length === 0) {
    console.error('Usage: node deob_unified.js <input.lua> [-o out.lua] [--plugin luraph_v15] [--no-devirt] [--debug] [--detect]');
    process.exit(2);
  }
  let ok = 0, bad = 0;
  for (const f of args.inputs) {
    try { (await deobfuscate(f, args)) ? ok++ : bad++; }
    catch (e) { process.stderr.write(`[!] failed on ${path.basename(f)}: ${e.message || e}\n`); bad++; }
  }
  if (bad > 0 && ok === 0) process.exit(1);
})();

module.exports = { deobfuscate };
