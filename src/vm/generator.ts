// ============================================================
//  Candy-obf-new  |  VM Generator
//  Generates the complete self-contained Luau VM runtime.
//
//  Output structure
//  ─────────────────
//  § 0  Luau env bootstrap (_G, bit32, _ENV)
//  § 1  Seeded xoshiro128** PRNG (per-build seed)
//  § 2  ARX stream decoder (paired-key XOR)
//  § 3  Anti-EMU + Anti-Tamper guards
//  § 4  Payload integrity check (FNV-1a)
//  § 5  Bytecode decoder (XOR + chunk reassembly)
//  § 6  VM execution engine
//       6a  RK helper
//       6b  Closure factory
//       6c  Dispatch loop (permuted opcodes + junk handlers)
//  § 7  Constant pool decoder
//  § 8  Proto deserialiser
//  § 9  Multi-stage loader / base-85 unpacker
//  § 10 Entry point (payload + execute call)
// ============================================================

import { LuauProto, VMConfig } from "./types";
import { Op } from "./opcodes";
import {
  serializeProto, encryptBytes, encodeBase85,
  chunkPayload, shuffleChunks, ArxMixer, fnv1a
} from "./encoder";
import {
  genGuardedExecution, genOpaquePredicate, genJunkHandler
} from "./anti_emu";

// ── Name-mangling (deterministic per seed) ───────────────────
class NamePool {
  private pool: string[] = [];
  private counter = 0;
  private mixer: ArxMixer;

  constructor(seed: number) { this.mixer = new ArxMixer(seed); }

  get(id: number): string {
    while (this.pool.length <= id) {
      const chars = "abcdefghijklmnopqrstuvwxyz";
      const UCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      let name = chars[this.mixer.next() % 26];
      const len = 3 + (this.mixer.next() % 5);
      for (let i = 1; i < len; i++) {
        const r = this.mixer.next();
        if (r % 3 === 0) name += UCHARS[r % 26];
        else if (r % 5 === 0) name += (r % 10).toString();
        else name += chars[r % 26];
      }
      this.pool.push(`_${name}`);
    }
    return this.pool[id];
  }

  // Shorthand generators
  n = (i: number) => this.get(i);
}

// ── Indent helper ────────────────────────────────────────────
function indent(code: string, level = 1): string {
  const pad = "  ".repeat(level);
  return code.split("\n").map(l => (l.trim() ? pad + l : l)).join("\n");
}

// ── Emit numeric table literal (Lua array) ───────────────────
function emitTable(bytes: number[], perLine = 16): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += perLine) {
    lines.push(bytes.slice(i, i + perLine).join(","));
  }
  return "{" + lines.join(",\n") + "}";
}

// ── Main generator ───────────────────────────────────────────
export function generateVM(proto: LuauProto, config: VMConfig): string {
  const {
    seed, opcodeMap, stringKey, integrityHash,
    antiEmu, multiStage, base85, antiTamper,
    opaquePredicates, junkPasses
  } = config;

  const np = new NamePool(seed[0] ^ seed[3]);

  // Reserve variable name slots
  const V = {
    // § 1 – PRNG
    PRNG_STATE : np.n(0),   // xoshiro128 state table
    PRNG_FN    : np.n(1),   // rng function

    // § 2 – Decoder
    DECODE_FN  : np.n(2),   // XOR byte stream decoder
    MIXER_STATE: np.n(3),   // ARX mixer closure

    // § 5 – Bytecode
    PAYLOAD    : np.n(4),   // raw byte array (literal or b85-decoded)
    PLAIN      : np.n(5),   // decrypted bytes

    // § 6 – VM
    VM_FN      : np.n(6),   // _execute(proto, upvals)
    RK_FN      : np.n(7),   // RK(x)
    MAKE_CLS   : np.n(8),   // closure factory

    // § 7 – Const pool
    DECODE_K   : np.n(9),   // decode constants

    // § 8 – Proto deserializer
    DESER_FN   : np.n(10),  // read_proto(bytes, cursor)

    // § 9 – Stage loader
    REASSEMBLE : np.n(11),  // reassemble chunks

    // § 10 – Entry
    ENV_VAR    : np.n(12),  // _G/_ENV reference
    BIT32_VAR  : np.n(13),  // bit32 local
    EXEC_ROOT  : np.n(14),  // top-level execute call

    // Temp vars
    I          : np.n(20),
    J          : np.n(21),
    K          : np.n(22),
    PC         : np.n(23),
    REGS       : np.n(24),
    INSTR      : np.n(25),
    OP_V       : np.n(26),
    A_V        : np.n(27),
    B_V        : np.n(28),
    C_V        : np.n(29),
    BX_V       : np.n(30),
    SBX_V      : np.n(31),
    CODE_V     : np.n(32),
    KT         : np.n(33),
    PROTOS_V   : np.n(34),
    UPVALS_V   : np.n(35),
    RET_V      : np.n(36),
    ARGS_V     : np.n(37),
    CURSOR_V   : np.n(38),
    BYTE_V     : np.n(39),
    MAXS_V     : np.n(40),
    NP_V       : np.n(41),
    UV_V       : np.n(42),
  };

  // ── Serialise + encrypt ──────────────────────────────────
  const plain = serializeProto(proto, opcodeMap);
  const { bytes: encrypted, hash } = encryptBytes(plain, seed, stringKey);

  // Opcode inverse map: scrambled → base  (embedded in Luau)
  const invMap: number[] = new Array(Op.__COUNT);
  for (let i = 0; i < Op.__COUNT; i++) invMap[opcodeMap[i]] = i;
  const invMapStr = invMap.join(",");

  // Per-build seed literals
  const s0 = seed[0].toString(); const s1 = seed[1].toString();
  const s2 = seed[2].toString(); const s3 = seed[3].toString();

  // Chunk & reorder
  const chunks = chunkPayload(encrypted);
  const { shuffled, order } = shuffleChunks(chunks, seed[2]);
  const orderStr = order.join(",");

  // ── § 0 – Env bootstrap ──────────────────────────────────
  const sec0 = `
local ${V.ENV_VAR} = (getfenv and getfenv(0)) or _ENV or _G
local ${V.BIT32_VAR} = bit32 or (${V.ENV_VAR}.bit32)
`.trim();

  // ── § 1 – xoshiro128** PRNG ──────────────────────────────
  const sec1 = `
-- § PRNG (xoshiro128** — per-build seed: ${s0},${s1},${s2},${s3})
local ${V.PRNG_STATE} = {${s0},${s1},${s2},${s3}}
local ${V.PRNG_FN}; do
  local ${V.I} = ${V.PRNG_STATE}
  local _b32 = ${V.BIT32_VAR}
  ${V.PRNG_FN} = function()
    local r = _b32.band(_b32.lrotate(_b32.band(${V.I}[2]*5,0xFFFFFFFF),7)*9,0xFFFFFFFF)
    local t = _b32.band(_b32.lshift(${V.I}[2],9),0xFFFFFFFF)
    ${V.I}[3] = _b32.bxor(${V.I}[3],${V.I}[1])
    ${V.I}[4] = _b32.bxor(${V.I}[4],${V.I}[2])
    ${V.I}[2] = _b32.bxor(${V.I}[2],${V.I}[3])
    ${V.I}[1] = _b32.bxor(${V.I}[1],${V.I}[4])
    ${V.I}[3] = _b32.bxor(${V.I}[3],t)
    ${V.I}[4] = _b32.rrotate(${V.I}[4],21)
    return r
  end
end
`.trim();

  // ── § 2 – ARX stream decoder ─────────────────────────────
  const initKey = stringKey >>> 0;
  const sec2 = `
-- § Decoder (ARX mixer + PRNG XOR stream)
local ${V.DECODE_FN}; do
  local _b32 = ${V.BIT32_VAR}
  local _ms  = ${initKey}
  local function _mixStep()
    _ms = _b32.band(_b32.bxor(_ms,_b32.rshift(_ms,16)),0xFFFFFFFF)
    _ms = _b32.band(_ms*0x45D9F3B,0xFFFFFFFF)
    _ms = _b32.band(_b32.bxor(_ms,_b32.rshift(_ms,16)),0xFFFFFFFF)
    _ms = _b32.band(_ms*0xBF5916A7,0xFFFFFFFF)
    _ms = _b32.band(_b32.bxor(_ms,_b32.rshift(_ms,16)),0xFFFFFFFF)
    return _ms
  end
  ${V.DECODE_FN} = function(enc)
    local out = {}
    for ${V.I}=1,#enc do
      local k = _b32.band(_b32.bxor(${V.PRNG_FN}(),_mixStep()),0xFF)
      out[${V.I}] = _b32.bxor(enc[${V.I}],k)
    end
    return out
  end
end
`.trim();

  // ── § 5 – Payload literal / base-85 ─────────────────────
  let sec5: string;
  if (base85) {
    const b85str = encodeBase85(encrypted);
    // b85 decode table embedded (no external lib needed)
    const charOrd = Array.from(
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
    ).map(c => c.charCodeAt(0)).join(",");

    sec5 = `
-- § Payload (Base-85 armoured)
local ${V.PAYLOAD}; do
  local _b32 = ${V.BIT32_VAR}
  local _ord = {${charOrd}}
  local _rev = {}; for i,v in ipairs(_ord) do _rev[v]=i-1 end
  local _s = "${b85str}"
  local _pad = (5-#_s%5)%5
  _s = _s .. string.rep(string.char(_ord[85]),_pad)
  local _raw = {}
  for i=1,#_s,5 do
    local v=0
    for j=0,4 do v=v*85+(_rev[_s:byte(i+j)] or 0) end
    _raw[#_raw+1]=_b32.rshift(v,24)
    _raw[#_raw+1]=_b32.band(_b32.rshift(v,16),0xFF)
    _raw[#_raw+1]=_b32.band(_b32.rshift(v,8),0xFF)
    _raw[#_raw+1]=_b32.band(v,0xFF)
  end
  ${V.PAYLOAD} = {table.unpack(_raw,1,#_raw-_pad)}
end
`.trim();
  } else {
    // Chunk-reordered literal
    const chunkLiterals = shuffled.map((ch, pos) =>
      `[${pos + 1}]={${ch.bytes.join(",")}}`
    ).join(",\n    ");
    const ORDER = np.n(60);
    sec5 = `
-- § Payload (chunk-reordered, ${chunks.length} chunks)
local ${V.PAYLOAD}; do
  local _ch = {${chunkLiterals}}
  local ${ORDER} = {${orderStr}}
  local _buf = {}
  for _pi, _si in ipairs(${ORDER}) do
    for _, b in ipairs(_ch[_pi]) do _buf[#_buf+1] = b end
  end
  ${V.PAYLOAD} = _buf
end
`.trim();
  }

  // ── § 3 – Anti-EMU / anti-tamper guards ─────────────────
  const sec3 = antiEmu || antiTamper
    ? "-- § Guards (generated at compile time)"
    : "";

  // ── § 6 – VM execution engine ────────────────────────────
  // Build the dispatch table: invMap maps scrambled → base opcode
  // then we compare against Op constants.
  // We inline the opcode values as literals (no symbolic names).

  const OPMAP_VAR = np.n(50);
  const DISPATCH  = np.n(51);

  // Generate junk handlers for unused opcode slots
  const junkHandlers: string[] = [];
  for (let j = 0; j < junkPasses; j++) {
    const junkOp = (Op.__COUNT + j);
    junkHandlers.push(`    -- junk handler ${j}\n    if ${V.OP_V}==${junkOp+100} then ${genJunkHandler(j)} end`);
  }

  // Opaque predicate for guard
  const opPred = opaquePredicates
    ? `if not ${genOpaquePredicate(seed[1])} then error("!") end\n  `
    : "";

  const sec6 = `
-- § VM (register-based, polymorphic dispatch)
local ${OPMAP_VAR} = {${invMapStr}}   -- scrambled→base

${V.MAKE_CLS} = nil  -- forward decl
local function ${V.VM_FN}(proto, envUp, varargs)
  ${opPred}local ${V.CODE_V}   = proto[1]
  local ${V.KT}      = proto[2]
  local ${V.PROTOS_V}= proto[3]
  local ${V.UPVALS_V}= envUp or {}
  local ${V.REGS}    = {}
  local ${V.PC}      = 1
  local ${V.MAXS_V}  = proto[4]

  -- Vararg handling
  local _vargs = varargs or {}

  -- RK: if x>=256 return K[x-256], else R[x]
  local function ${V.RK_FN}(x)
    if x >= 256 then return ${V.KT}[x-256] else return ${V.REGS}[x] end
  end

  -- Execution loop
  while ${V.PC} <= #${V.CODE_V} do
    local ${V.INSTR} = ${V.CODE_V}[${V.PC}]
    ${V.PC} = ${V.PC} + 1

    -- Decode fields
    local ${V.OP_V}  = ${OPMAP_VAR}[${V.INSTR}[1]] -- remap scrambled→base
    local ${V.A_V}   = ${V.INSTR}[2]
    local ${V.B_V}   = ${V.INSTR}[3]
    local ${V.C_V}   = ${V.INSTR}[4]
    local ${V.BX_V}  = ${V.INSTR}[5]
    local ${V.SBX_V} = ${V.INSTR}[6]

    -- ── Dispatch ──────────────────────────────────────────
    if     ${V.OP_V}==${Op.MOVE}     then ${V.REGS}[${V.A_V}]=${V.REGS}[${V.B_V}]
    elseif ${V.OP_V}==${Op.LOADK}    then ${V.REGS}[${V.A_V}]=${V.KT}[${V.BX_V}]
    elseif ${V.OP_V}==${Op.LOADBOOL} then
      ${V.REGS}[${V.A_V}]=(${V.B_V}~=0)
      if ${V.C_V}~=0 then ${V.PC}=${V.PC}+1 end
    elseif ${V.OP_V}==${Op.LOADNIL}  then
      for _ni=${V.A_V},${V.B_V} do ${V.REGS}[_ni]=nil end

    elseif ${V.OP_V}==${Op.GETUPVAL} then ${V.REGS}[${V.A_V}]=${V.UPVALS_V}[${V.B_V}+1]
    elseif ${V.OP_V}==${Op.SETUPVAL} then ${V.UPVALS_V}[${V.B_V}+1]=${V.REGS}[${V.A_V}]
    elseif ${V.OP_V}==${Op.GETTABUP} then ${V.REGS}[${V.A_V}]=${V.UPVALS_V}[${V.B_V}+1][${V.RK_FN}(${V.C_V})]
    elseif ${V.OP_V}==${Op.SETTABUP} then ${V.UPVALS_V}[${V.A_V}+1][${V.RK_FN}(${V.B_V})]=${V.RK_FN}(${V.C_V})

    elseif ${V.OP_V}==${Op.GETTABLE} then ${V.REGS}[${V.A_V}]=${V.REGS}[${V.B_V}][${V.RK_FN}(${V.C_V})]
    elseif ${V.OP_V}==${Op.SETTABLE} then ${V.REGS}[${V.A_V}][${V.RK_FN}(${V.B_V})]=${V.RK_FN}(${V.C_V})
    elseif ${V.OP_V}==${Op.NEWTABLE} then ${V.REGS}[${V.A_V}]={}
    elseif ${V.OP_V}==${Op.SELF}     then
      ${V.REGS}[${V.A_V}+1]=${V.REGS}[${V.B_V}]
      ${V.REGS}[${V.A_V}]=${V.REGS}[${V.B_V}][${V.RK_FN}(${V.C_V})]
    elseif ${V.OP_V}==${Op.SETLIST}  then
      local _t=${V.REGS}[${V.A_V}]
      local _n=${V.B_V}==0 and (#${V.REGS}-${V.A_V}) or ${V.B_V}
      local _base=(${V.C_V}-1)*50
      for _si=1,_n do _t[_base+_si]=${V.REGS}[${V.A_V}+_si] end

    -- Arithmetic
    elseif ${V.OP_V}==${Op.ADD}  then ${V.REGS}[${V.A_V}]=${V.RK_FN}(${V.B_V})+${V.RK_FN}(${V.C_V})
    elseif ${V.OP_V}==${Op.SUB}  then ${V.REGS}[${V.A_V}]=${V.RK_FN}(${V.B_V})-${V.RK_FN}(${V.C_V})
    elseif ${V.OP_V}==${Op.MUL}  then ${V.REGS}[${V.A_V}]=${V.RK_FN}(${V.B_V})*${V.RK_FN}(${V.C_V})
    elseif ${V.OP_V}==${Op.DIV}  then ${V.REGS}[${V.A_V}]=${V.RK_FN}(${V.B_V})/${V.RK_FN}(${V.C_V})
    elseif ${V.OP_V}==${Op.MOD}  then ${V.REGS}[${V.A_V}]=${V.RK_FN}(${V.B_V})%${V.RK_FN}(${V.C_V})
    elseif ${V.OP_V}==${Op.POW}  then ${V.REGS}[${V.A_V}]=${V.RK_FN}(${V.B_V})^${V.RK_FN}(${V.C_V})
    elseif ${V.OP_V}==${Op.IDIV} then ${V.REGS}[${V.A_V}]=math.floor(${V.RK_FN}(${V.B_V})/${V.RK_FN}(${V.C_V}))

    -- Bitwise
    elseif ${V.OP_V}==${Op.BAND} then ${V.REGS}[${V.A_V}]=${V.BIT32_VAR}.band(${V.RK_FN}(${V.B_V}),${V.RK_FN}(${V.C_V}))
    elseif ${V.OP_V}==${Op.BOR}  then ${V.REGS}[${V.A_V}]=${V.BIT32_VAR}.bor(${V.RK_FN}(${V.B_V}),${V.RK_FN}(${V.C_V}))
    elseif ${V.OP_V}==${Op.BXOR} then ${V.REGS}[${V.A_V}]=${V.BIT32_VAR}.bxor(${V.RK_FN}(${V.B_V}),${V.RK_FN}(${V.C_V}))
    elseif ${V.OP_V}==${Op.SHL}  then ${V.REGS}[${V.A_V}]=${V.BIT32_VAR}.lshift(${V.RK_FN}(${V.B_V}),${V.RK_FN}(${V.C_V}))
    elseif ${V.OP_V}==${Op.SHR}  then ${V.REGS}[${V.A_V}]=${V.BIT32_VAR}.rshift(${V.RK_FN}(${V.B_V}),${V.RK_FN}(${V.C_V}))

    -- Unary
    elseif ${V.OP_V}==${Op.UNM}  then ${V.REGS}[${V.A_V}]=-${V.REGS}[${V.B_V}]
    elseif ${V.OP_V}==${Op.BNOT} then ${V.REGS}[${V.A_V}]=${V.BIT32_VAR}.bnot(${V.REGS}[${V.B_V}])
    elseif ${V.OP_V}==${Op.NOT}  then ${V.REGS}[${V.A_V}]=not ${V.REGS}[${V.B_V}]
    elseif ${V.OP_V}==${Op.LEN}  then ${V.REGS}[${V.A_V}]=#${V.REGS}[${V.B_V}]

    -- Concat
    elseif ${V.OP_V}==${Op.CONCAT} then
      local _parts={}
      for _ci=${V.B_V},${V.C_V} do _parts[#_parts+1]=tostring(${V.REGS}[_ci]) end
      ${V.REGS}[${V.A_V}]=table.concat(_parts)

    -- Control flow
    elseif ${V.OP_V}==${Op.JMP}     then ${V.PC}=${V.PC}+${V.SBX_V}
    elseif ${V.OP_V}==${Op.EQ}      then if (${V.RK_FN}(${V.B_V})==${V.RK_FN}(${V.C_V}))~=(${V.A_V}~=0) then ${V.PC}=${V.PC}+1 end
    elseif ${V.OP_V}==${Op.LT}      then if (${V.RK_FN}(${V.B_V})<${V.RK_FN}(${V.C_V}))~=(${V.A_V}~=0) then ${V.PC}=${V.PC}+1 end
    elseif ${V.OP_V}==${Op.LE}      then if (${V.RK_FN}(${V.B_V})<=${V.RK_FN}(${V.C_V}))~=(${V.A_V}~=0) then ${V.PC}=${V.PC}+1 end
    elseif ${V.OP_V}==${Op.TEST}    then if (not not ${V.REGS}[${V.A_V}])~=(${V.C_V}~=0) then ${V.PC}=${V.PC}+1 end
    elseif ${V.OP_V}==${Op.TESTSET} then
      if (not not ${V.REGS}[${V.B_V}])~=(${V.C_V}~=0) then ${V.PC}=${V.PC}+1
      else ${V.REGS}[${V.A_V}]=${V.REGS}[${V.B_V}] end

    -- Calls
    elseif ${V.OP_V}==${Op.CALL} then
      local _fn=${V.REGS}[${V.A_V}]
      local _args={}
      if ${V.B_V}==1 then -- no args
      elseif ${V.B_V}==0 then for _ai=${V.A_V}+1,#${V.REGS} do _args[#_args+1]=${V.REGS}[_ai] end
      else for _ai=${V.A_V}+1,${V.A_V}+${V.B_V}-1 do _args[#_args+1]=${V.REGS}[_ai] end end
      local _res={_fn(table.unpack(_args))}
      if ${V.C_V}==0 then for _ri=0,#_res-1 do ${V.REGS}[${V.A_V}+_ri]=_res[_ri+1] end
      elseif ${V.C_V}>1 then for _ri=0,${V.C_V}-2 do ${V.REGS}[${V.A_V}+_ri]=_res[_ri+1] end end

    elseif ${V.OP_V}==${Op.TAILCALL} then
      local _fn=${V.REGS}[${V.A_V}]
      local _args={}
      for _ai=${V.A_V}+1,${V.A_V}+${V.B_V}-1 do _args[#_args+1]=${V.REGS}[_ai] end
      return _fn(table.unpack(_args))

    elseif ${V.OP_V}==${Op.RETURN} then
      if ${V.B_V}==1 then return
      elseif ${V.B_V}==0 then
        local _r={}; for _ri=${V.A_V},#${V.REGS} do _r[#_r+1]=${V.REGS}[_ri] end; return table.unpack(_r)
      else
        local _r={}; for _ri=${V.A_V},${V.A_V}+${V.B_V}-2 do _r[#_r+1]=${V.REGS}[_ri] end; return table.unpack(_r)
      end

    -- Loops
    elseif ${V.OP_V}==${Op.FORPREP} then
      ${V.REGS}[${V.A_V}]=${V.REGS}[${V.A_V}]-${V.REGS}[${V.A_V}+2]
      ${V.PC}=${V.PC}+${V.SBX_V}
    elseif ${V.OP_V}==${Op.FORLOOP} then
      ${V.REGS}[${V.A_V}]=${V.REGS}[${V.A_V}]+${V.REGS}[${V.A_V}+2]
      local _ok=(${V.REGS}[${V.A_V}+2]>0 and ${V.REGS}[${V.A_V}]<=${V.REGS}[${V.A_V}+1]) or
                (${V.REGS}[${V.A_V}+2]<0 and ${V.REGS}[${V.A_V}]>=${V.REGS}[${V.A_V}+1])
      if _ok then ${V.PC}=${V.PC}+${V.SBX_V}; ${V.REGS}[${V.A_V}+3]=${V.REGS}[${V.A_V}] end
    elseif ${V.OP_V}==${Op.TFORCALL} then
      local _res={${V.REGS}[${V.A_V}](${V.REGS}[${V.A_V}+1],${V.REGS}[${V.A_V}+2])}
      for _ti=1,${V.C_V} do ${V.REGS}[${V.A_V}+2+_ti]=_res[_ti] end
    elseif ${V.OP_V}==${Op.TFORLOOP} then
      if ${V.REGS}[${V.A_V}+3]~=nil then
        ${V.REGS}[${V.A_V}+2]=${V.REGS}[${V.A_V}+3]; ${V.PC}=${V.PC}+${V.SBX_V}
      end

    -- Closures
    elseif ${V.OP_V}==${Op.CLOSURE} then
      ${V.REGS}[${V.A_V}]=${V.MAKE_CLS}(${V.PROTOS_V}[${V.BX_V}+1],${V.UPVALS_V},${V.REGS})
    elseif ${V.OP_V}==${Op.VARARG} then
      if ${V.B_V}==0 then for _vi=1,#_vargs do ${V.REGS}[${V.A_V}+_vi-1]=_vargs[_vi] end
      else for _vi=0,${V.B_V}-2 do ${V.REGS}[${V.A_V}+_vi]=_vargs[_vi+1] end end
    elseif ${V.OP_V}==${Op.CLOSE} then -- upvalue close (GC hint, no-op here)
    elseif ${V.OP_V}==${Op.GETGLOBAL} then ${V.REGS}[${V.A_V}]=${V.UPVALS_V}[1][${V.KT}[${V.BX_V}]]
    elseif ${V.OP_V}==${Op.SETGLOBAL} then ${V.UPVALS_V}[1][${V.KT}[${V.BX_V}]]=${V.REGS}[${V.A_V}]
${junkHandlers.join("\n")}
    end -- dispatch
  end -- while
end -- vm_fn

-- Closure factory: captures upvals + register-based upvalue binding
${V.MAKE_CLS} = function(subProto, parentUpvals, parentRegs)
  local _uvs = {}
  for _ui, _ud in ipairs(subProto[5]) do
    if _ud[1]==1 then _uvs[_ui] = {parentRegs, _ud[2]+1}  -- instack ref
    else              _uvs[_ui] = parentUpvals end          -- chained upval
  end
  return function(...)
    -- resolve instack upvals (simple reference by index)
    local _resolved = {}
    for _ui, _ref in ipairs(_uvs) do
      if type(_ref)=="table" and _ref[1] then
        _resolved[_ui] = _ref[1][_ref[2]]
      else
        _resolved[_ui] = _ref
      end
    end
    return ${V.VM_FN}(subProto, _resolved, {...})
  end
end
`.trim();

  // ── § 7 – Constant decoder ───────────────────────────────
  const strKeyHex = (stringKey >>> 0).toString(16).toUpperCase();
  const sec7 = `
-- § Constant pool decoder
local function ${V.DECODE_K}(raw, idx)
  local _b32 = ${V.BIT32_VAR}
  local _t=raw[idx]; idx=idx+1
  if _t==0 then return nil,idx
  elseif _t==1 then local v=raw[idx]; return v~=0,idx+1
  elseif _t==2 then
    -- IEEE-754 f64 little-endian (8 bytes)
    local _bytes={}
    for _fi=0,7 do _bytes[_fi]=raw[idx+_fi] end
    idx=idx+8
    local sign = _bytes[7]>=128 and -1 or 1
    local exp  = _b32.band(_b32.rshift(_bytes[7],0)*256+_bytes[6], 0x7FF0)
    local man  = 0
    for _bi=5,0,-1 do man=man*256+_bytes[_bi] end
    man = man + _b32.band(_bytes[6],0xF)*0x100000000
    if exp==0x7FF0 then return sign*(man==0 and math.huge or -(0/0)),idx end
    if exp==0 then return sign*man*2^(-1074),idx end
    return sign*(1+man*2^(-52))*2^(_b32.rshift(exp,4)-1023),idx
  elseif _t==3 then
    local _len=raw[idx]+raw[idx+1]*256; idx=idx+2
    -- Paired-key string decode (k1, k2 derived from ARX mixer)
    local _ms=0x${strKeyHex}
    local function _mixStep()
      _ms=_b32.band(_b32.bxor(_ms,_b32.rshift(_ms,16)),0xFFFFFFFF)
      _ms=_b32.band(_ms*0x45D9F3B,0xFFFFFFFF)
      _ms=_b32.band(_b32.bxor(_ms,_b32.rshift(_ms,16)),0xFFFFFFFF)
      return _ms
    end
    local _chars={}
    for _ci=1,_len do
      local _k=_ci%2==1 and _b32.band(_mixStep(),0xFF) or _b32.band(_mixStep(),0xFF)
      _chars[_ci]=string.char(_b32.bxor(raw[idx],_k)); idx=idx+1
    end
    return table.concat(_chars),idx
  elseif _t==4 then
    local _pi=raw[idx]+raw[idx+1]*256; idx=idx+2
    return _pi,idx   -- proto index (resolved later)
  end
  return nil,idx
end
`.trim();

  // ── § 8 – Proto deserialiser ─────────────────────────────
  const sec8 = `
-- § Proto deserialiser
local function ${V.DESER_FN}(bytes)
  local _b32 = ${V.BIT32_VAR}
  local _idx=1

  local function _u8()  local v=bytes[_idx]; _idx=_idx+1; return v end
  local function _u16() local v=bytes[_idx]+bytes[_idx+1]*256; _idx=_idx+2; return v end

  local function _readProto()
    local _np    = _u8()   -- numParams
    local _va    = _u8()   -- isVararg
    local _ms2   = _u8()   -- maxStackSize
    local _nc    = _u16()  -- numConsts
    local _K={}
    for _ki=1,_nc do
      local v; v,_idx=${V.DECODE_K}(bytes,_idx)
      _K[_ki-1]=v
    end
    local _ni  = _u16()
    local _code={}
    for _ii=1,_ni do
      local _A=_u8(); local _B=_u16(); local _C=_u16(); local _op=_u8()
      local _Bx=_B*512+_C
      local _sBx=_Bx-131071
      _code[_ii]={_op,_A,_B,_C,_Bx,_sBx}
    end
    local _npr=_u8()
    local _protos={}
    for _pi=1,_npr do _protos[_pi]=_readProto() end
    local _nuv=_u8()
    local _uvs={}
    for _ui=1,_nuv do
      local _ins=_u8(); local _uidx=_u8()
      _uvs[_ui]={_ins,_uidx}
    end
    -- proto layout: {code, constants, protos, maxStack, upvals}
    return {_code,_K,_protos,_ms2,_uvs,_np,_va==1}
  end

  return _readProto()
end
`.trim();

  // ── § 9 – Multi-stage loader ─────────────────────────────
  const sec9 = multiStage ? `
-- § Multi-stage loader (stage 2 wraps stage 1 decrypt)
local function _stage1(payload)
  return ${V.DECODE_FN}(payload)
end
local function _stage2(plain)
  return ${V.DESER_FN}(plain)
end
local function _load(payload)
  return _stage2(_stage1(payload))
end
`.trim() : `
local function _load(payload)
  return ${V.DESER_FN}(${V.DECODE_FN}(payload))
end`.trim();

  // ── § 10 – Entry point ───────────────────────────────────
  const mainBody = `
local _proto = _load(${V.PAYLOAD})
local _env = ${V.ENV_VAR}
${V.VM_FN}(_proto, {_env}, {})`.trim();

  const sec10 = antiEmu || antiTamper
    ? genGuardedExecution(mainBody, V.PAYLOAD, hash, { antiEmu, antiTamper })
    : mainBody;

  // ── Assemble final output ────────────────────────────────
  const sections = [sec0, sec1, sec2, sec5, sec3, sec7, sec8, sec9, sec6, sec10];
  return sections
    .filter(Boolean)
    .map(s => s.trim())
    .join("\n\n");
}

// ── Config factory (random per-build) ───────────────────────
export function makeConfig(
  overrides?: Partial<VMConfig>
): VMConfig {
  const rng = () => (Math.random() * 0x100000000) >>> 0;
  const { generateOpcodeMap } = require("./opcodes");

  const seed: [number, number, number, number] = [rng(), rng(), rng(), rng()];
  return {
    seed,
    opcodeMap:         generateOpcodeMap(seed),
    stringKey:         rng(),
    integrityHash:     0,         // computed after serialisation
    antiEmu:           true,
    multiStage:        true,
    base85:            true,
    antiTamper:        true,
    opaquePredicates:  true,
    junkPasses:        4,
    ...overrides,
  };
}

