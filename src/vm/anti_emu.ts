// ============================================================
//  Candy-obf-new  |  Anti-EMU / Anti-Tamper
//  Generates Luau code snippets for runtime protection.
//
//  Defended threats:
//  • EMU returns clock/tick/time == 0 always  → timing gate
//  • EMU sets debug = nil                     → debug probe
//  • EMU dispatch-based VM analysis           → opaque predicates
//  • Hook/closure injection                   → closure detection
//  • Stack/trace inspection                   → traceback guard
//  • Environment fingerprinting               → Roblox API probe
//  • Static analysis of dispatch table        → junk handler injection
// ============================================================

import { ArxMixer } from "./encoder";

// ── Name-mangling helpers ────────────────────────────────────
let _nameCounter = 0;

function mkName(seed?: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const m = new ArxMixer(seed ?? (_nameCounter++ * 0x9E3779B9));
  const len = 4 + (m.next() % 6);
  let name = chars[m.next() % 52];          // must start with letter
  for (let i = 1; i < len; i++) {
    name += chars[m.next() % 52];
    if (m.next() % 4 === 0) name += (m.next() % 10).toString();
  }
  return name;
}

// ── Anti-EMU timing gate ─────────────────────────────────────
// EMU returns 0 for tick() and os.clock() always.
// We busy-loop then check: if BOTH return 0, we're in EMU.
// We also check that the function itself is not nil/spoofed.
export function genTimingCheck(varName: string): string {
  const tv0 = mkName(0xA1);
  const tv1 = mkName(0xA2);
  const fn  = mkName(0xA3);
  const acc = mkName(0xA4);
  return `
local ${varName} = false
;(function()
  local ${fn} = (rawget(_G,"tick") or (os and os.clock))
  if type(${fn}) ~= "function" then return end
  local ${tv0} = ${fn}()
  local ${acc} = 0
  for _i = 1, 800 do ${acc} = ${acc} + _i end  -- busy work
  local ${tv1} = ${fn}()
  -- EMU: both calls return literal 0
  if not (${tv0} == 0 and ${tv1} == 0) then
    ${varName} = true
  end
end)()`.trim();
}

// ── Debug library probe ──────────────────────────────────────
// Real Roblox: debug is a table with restricted methods.
// Many EMUs: debug = nil, or debug.traceback = nil/stub.
// We DON'T require debug to exist (some sandboxes strip it),
// but if it exists, it must behave correctly.
export function genDebugProbe(varName: string): string {
  const db  = mkName(0xB1);
  const ok  = mkName(0xB2);
  const res = mkName(0xB3);
  return `
local ${varName} = true
;(function()
  local ${db} = rawget(_G,"debug") or debug
  if ${db} == nil then return end          -- stripped sandbox: allow
  if type(${db}) ~= "table" then
    ${varName} = false; return
  end
  -- traceback must be callable and return a string
  if type(${db}.traceback) ~= "function" then
    ${varName} = false; return
  end
  local ${ok}, ${res} = pcall(${db}.traceback)
  if not ${ok} or type(${res}) ~= "string" then
    ${varName} = false; return
  end
end)()`.trim();
}

// ── Roblox environment fingerprint ───────────────────────────
// Real Roblox: game, workspace, script, Players all exist.
// Most EMUs expose a limited _G with no Roblox services.
export function genEnvFingerprint(varName: string): string {
  const ok1 = mkName(0xC1);
  const ok2 = mkName(0xC2);
  const g   = mkName(0xC3);
  const ws  = mkName(0xC4);
  return `
local ${varName} = false
;(function()
  local ${g}  = rawget(_G,"game")
  local ${ws} = rawget(_G,"workspace")
  local ${ok1} = (${g}  ~= nil and typeof ~= nil)
  local ${ok2} = (${ws} ~= nil)
  ${varName} = ${ok1} and ${ok2}
end)()`.trim();
}

// ── Stack depth / traceback guard ───────────────────────────
// Some analysis tools inject wrapper frames around the entry.
// We check that our call depth is within expected bounds.
export function genStackGuard(varName: string, maxDepth = 6): string {
  const db  = mkName(0xD1);
  const tb  = mkName(0xD2);
  const cnt = mkName(0xD3);
  return `
local ${varName} = true
;(function()
  local ${db} = rawget(_G,"debug") or debug
  if not (${db} and type(${db}.traceback) == "function") then return end
  local _, ${tb} = pcall(${db}.traceback)
  if type(${tb}) ~= "string" then return end
  local ${cnt} = 0
  for _ in (${tb}):gmatch("[^\\n]+") do ${cnt} = ${cnt} + 1 end
  if ${cnt} > ${maxDepth} then ${varName} = false end
end)()`.trim();
}

// ── Hook / closure detection ─────────────────────────────────
// Check that key Roblox functions haven't been hooked by
// comparing their addresses via tostring (metamethod spoofing
// shows up as non-"function" or mismatched type).
export function genHookDetect(varName: string): string {
  const fns = mkName(0xE1);
  const ok  = mkName(0xE2);
  return `
local ${varName} = true
;(function()
  local ${fns} = {
    rawget, rawset, rawequal, rawlen,
    tostring, tonumber, type, select,
    setmetatable, getmetatable, pairs, ipairs,
    table.insert, table.remove, math.floor
  }
  for _, f in ipairs(${fns}) do
    if type(f) ~= "function" then
      ${varName} = false; return
    end
    -- newcclosure / hookfunction wrapping leaves a detectable trace
    local ${ok}, s = pcall(tostring, f)
    if not ${ok} or not s:find("function") then
      ${varName} = false; return
    end
  end
end)()`.trim();
}

// ── Math precision fingerprint ───────────────────────────────
// EMUs with incorrect float arithmetic will fail this.
export function genMathCheck(varName: string): string {
  const p = mkName(0xF1);
  const e = mkName(0xF2);
  return `
local ${varName} = true
;(function()
  -- IEEE-754 must hold; EMUs with wrong float impl will fail
  local ${p} = math.pi
  local ${e} = math.exp(1)
  if not (${p} > 3.14159 and ${p} < 3.14160) then ${varName} = false; return end
  if not (${e} > 2.71828 and ${e} < 2.71829) then ${varName} = false; return end
  -- Modular arithmetic check (2^32 wrap)
  if (2^32) ~= 4294967296 then ${varName} = false end
end)()`.trim();
}

// ── Runtime integrity mixer ──────────────────────────────────
// FNV-1a style check of the payload bytes at runtime.
// `payloadVar` is the Lua variable holding the byte table.
// Returns a boolean variable.
export function genIntegrityCheck(
  varName: string,
  payloadVar: string,
  expectedHash: number
): string {
  const h  = mkName(0x91);
  const b  = mkName(0x92);
  const ex = (expectedHash >>> 0).toString(16).toUpperCase();
  return `
local ${varName} = false
;(function()
  local ${h} = 0x811C9DC5
  for _, ${b} in ipairs(${payloadVar}) do
    ${h} = bit32.bxor(${h}, ${b})
    ${h} = bit32.band(${h} * 0x01000193, 0xFFFFFFFF)
  end
  ${varName} = (${h} == 0x${ex})
end)()`.trim();
}

// ── Opaque predicates generator ──────────────────────────────
// Produces always-true conditions that resist static analysis.
// Resistance: the predicate value depends on runtime environment,
// making it impossible to evaluate statically.
export function genOpaquePredicate(mixerSeed: number): string {
  const m  = new ArxMixer(mixerSeed);
  const a  = (m.next() % 998) + 2;          // 2..999 (even-ish)
  const b  = (m.next() % 100) + 1;
  const vx = mkName(0x30 + (mixerSeed & 0xF));
  const vy = mkName(0x40 + (mixerSeed & 0xF));
  // x*(x+1) is always even — but we compute it from an env value
  // so a static analyser can't fold it.
  return `(function()local ${vx}=math.floor(os and os.clock and os.clock()*0+${a} or ${a});local ${vy}=${vx}*(${vx}+1);return ${vy}%2==0 end)()`;
}

// ── Junk instruction handler ─────────────────────────────────
// Returns a Luau handler body that does nothing useful but
// costs the same amount of work as a real handler, confusing
// opcode frequency analysis.
export function genJunkHandler(seed: number): string {
  const m   = new ArxMixer(seed);
  const acc = mkName(seed);
  const k   = m.next() & 0xFFFF;
  const p   = (m.next() % 12) + 2;
  return `local ${acc}=${k};for _ = 1,${p} do ${acc}=bit32.bxor(${acc},${acc}*7+13) end`;
}

// ── Payload-gating guard (combines all checks) ───────────────
// Returns Luau code that only runs `bodyCode` if all checks pass.
export function genGuardedExecution(
  bodyCode:      string,
  payloadVar:    string,
  expectedHash:  number,
  opts: {
    antiEmu:    boolean;
    antiTamper: boolean;
  }
): string {
  const lines: string[] = [];
  const vars: { name: string; code: string }[] = [];

  if (opts.antiEmu) {
    const v = mkName(0x11);
    vars.push({ name: v, code: genTimingCheck(v) });
    const v2 = mkName(0x12);
    vars.push({ name: v2, code: genEnvFingerprint(v2) });
    const v3 = mkName(0x13);
    vars.push({ name: v3, code: genMathCheck(v3) });
  }

  if (opts.antiTamper) {
    const v = mkName(0x21);
    vars.push({ name: v, code: genHookDetect(v) });
    const v2 = mkName(0x22);
    vars.push({ name: v2, code: genDebugProbe(v2) });
  }

  const vi = mkName(0x31);
  vars.push({ name: vi, code: genIntegrityCheck(vi, payloadVar, expectedHash) });

  for (const { code } of vars) lines.push(code);

  const cond = vars.map(v => v.name).join(" and ");
  lines.push(`if ${cond} then`);
  lines.push(bodyCode.split("\n").map(l => "  " + l).join("\n"));
  lines.push(`end`);

  return lines.join("\n");
}

