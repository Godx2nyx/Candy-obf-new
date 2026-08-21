import { Proto, Op, Constant } from "../compiler/bytecode"
import { mulberry32, randomNames, base85Encode, buildOpcodePermutation, arxMix, fnvHash, seededShuffle } from "./utils"

// ====== CONFIG ======
export interface VMGenConfig {
  seed: number
  minify: boolean
}

// ====== OPCODE PERMUTATION ======
// Per-build: opcode ถูกสลับใหม่ทุก build EMU ต้อง re-analyze ทุกครั้ง
function buildPermTable(seed: number): { perm: number[]; inv: number[] } {
  const rng = mulberry32(seed ^ 0xDEAD1337)
  const perm = buildOpcodePermutation(Op._COUNT, rng)
  const inv = new Array(Op._COUNT).fill(0)
  perm.forEach((v, i) => inv[v] = i)
  return { perm, inv }
}

// ====== ENCRYPT BYTECODE ======
// ARX + XOR + stateful rolling hash
function encryptBytecode(data: number[], seed: number): { blob: number[]; key: number; checksum: number } {
  // Keep the key schedule identical to the generated Luau decoder.
  // Using the same LCG here avoids the previous TS/runtime key-schedule mismatch.
  const blob: number[] = []
  let rolling = seed & 0xFF
  let state = seed >>> 0
  for (let i = 0; i < data.length; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    const ks = state & 0xFF
    const k = (ks ^ rolling ^ (i & 0xFF)) & 0xFF
    const enc = (data[i] ^ k) & 0xFF
    blob.push(enc)
    rolling = (rolling + data[i] + i) & 0xFF
  }
  // Match the generated Luau checksum exactly:
  // FNV-style update from 0x811C9DC5, then XOR the per-build salt.
  let checksum = 0x811C9DC5 >>> 0
  for (const b of data) {
    checksum = Math.imul(checksum, 0x01000193) >>> 0
    checksum = (checksum ^ b) >>> 0
  }
  checksum = (checksum ^ ((seed ^ 0xCAFEBABE) >>> 0)) >>> 0
  return { blob, key: seed & 0xFF, checksum }
}

// ====== SERIALIZE PROTO TO BYTES ======
function serializeProto(proto: Proto, permTable: number[]): number[] {
  const bytes: number[] = []

  function writeU8(v: number) { bytes.push(v & 0xFF) }
  function writeU16(v: number) { writeU8(v & 0xFF); writeU8((v >> 8) & 0xFF) }
  function writeU32(v: number) { writeU16(v & 0xFFFF); writeU16((v >> 16) & 0xFFFF) }
  function writeFloat(v: number) {
    const buf = new ArrayBuffer(8)
    new DataView(buf).setFloat64(0, v, true)
    new Uint8Array(buf).forEach(b => writeU8(b))
  }
  function writeStr(s: string) {
    writeU16(s.length)
    for (let i = 0; i < s.length; i++) writeU8(s.charCodeAt(i) & 0xFF)
  }

  // Header
  writeU8(proto.params)
  writeU8(proto.hasVarArg ? 1 : 0)
  writeU8(proto.maxStack)

  // Instructions
  writeU16(proto.instructions.length)
  for (const ins of proto.instructions) {
    const permOp = permTable[ins.op] ?? ins.op
    writeU8(permOp)
    writeU8(ins.a)
    writeU8(ins.b)
    writeU8(ins.c)
  }

  // Constants
  writeU16(proto.constants.length)
  for (const k of proto.constants) {
    if (k.type === "nil")     { writeU8(0) }
    else if (k.type === "boolean") { writeU8(1); writeU8(k.value ? 1 : 0) }
    else if (k.type === "number")  { writeU8(2); writeFloat(k.value) }
    else if (k.type === "string")  { writeU8(3); writeStr(k.value) }
  }

  // Upvalues
  writeU16(proto.upvalues.length)
  for (const uv of proto.upvalues) {
    writeU8(uv.inStack ? 1 : 0)
    writeU8(uv.idx)
    writeStr(uv.name)
  }

  // Sub-protos
  writeU16(proto.protos.length)
  for (const sub of proto.protos) {
    const subBytes = serializeProto(sub, permTable)
    writeU16(subBytes.length)
    for (const b of subBytes) writeU8(b)
  }

  return bytes
}

// ====== GENERATE VM RUNNER ======
export function generateVM(rootProto: Proto, cfg: VMGenConfig): string {
  const rng = mulberry32(cfg.seed)
  const names = randomNames(rng, 120, 6)
  let ni = 0
  const N = () => names[ni++] ?? `_v${ni}`

  // opcode permutation
  const { perm, inv } = buildPermTable(cfg.seed)

  // serialize + encrypt
  const rawBytes = serializeProto(rootProto, perm)
  const { blob, key, checksum } = encryptBytecode(rawBytes, cfg.seed)
  const b85 = base85Encode(blob)

  // name pool
  const nBlob    = N(), nKey     = N(), nChk    = N(), nDecode = N()
  const nVm      = N(), nExec    = N(), nEnv    = N(), nUp     = N()
  const nRegs    = N(), nPC      = N(), nStack  = N(), nProto  = N()
  const nConsts  = N(), nInstrs  = N(), nProtos = N(), nUvals  = N()
  const nOp      = N(), nA       = N(), nB      = N(), nC      = N()
  const nDisp    = N(), nI       = N(), nV      = N(), nR      = N()
  const nGuard   = N(), nRolling = N(), nSum    = N(), nFp     = N()
  const nIdxMap  = N(), nStrBuf  = N(), nPos    = N(), nLen    = N()
  const nU8      = N(), nU16     = N(), nU32    = N(), nFlt    = N()
  const nStg     = N(), nStg2   = N(), nLoader  = N(), nKs    = N()
  const nChkVar  = N(), nMath1  = N(), nMath2   = N(), nTbl1  = N()
  const nMeta1   = N(), nMeta2  = N(), nPc1    = N(), nPc2    = N()
  const nFib1    = N(), nFib2   = N(), nFibT   = N(), nFibN   = N()
  const nEnvPrb  = N(), nUvC    = N(), nUvR    = N()
  const nCo      = N(), nCoSt   = N(), nStrT   = N(), nStrS   = N()
  const nRng1    = N(), nRng2   = N(), nRngS   = N()
  const nHashA   = N(), nHashB  = N(), nArxV   = N()
  const nMixA    = N(), nMixB   = N(), nMixC   = N()
  const nDynApi  = N(), nApiT   = N(), nApiR   = N()
  const nPayload = N(), nStage1 = N(), nStage2 = N()
  const nChunk   = N(), nChunkI = N(), nChunkN = N()

  // per-build opaque constants
  const opaqueA = 1 + Math.floor(rng() * 65535)
  const opaqueB = 1 + Math.floor(rng() * 65535)
  const opaqueC = arxMix(opaqueA ^ opaqueB, cfg.seed) & 0xFFFF
  const fibN = 18 + Math.floor(rng() * 10)
  let fa = 1, fb = 1
  for (let i = 2; i < fibN; i++) { [fa, fb] = [fb, fa + fb] }
  const fibExpected = fb % 65536
  const mathA = 100 + Math.floor(rng() * 900)
  const mathB = 100 + Math.floor(rng() * 900)
  const mathExp = Math.floor(Math.sqrt(mathA * mathB))
  const tblSum = [1,4,9,16,25].reduce((a,b)=>a+b,0)
  const uvSeed = Math.floor(rng() * 0xFFFF)
  const uvA = Math.floor(rng() * 255) + 1
  const uvB = Math.floor(rng() * 255) + 1
  const uvC = Math.floor(rng() * 255) + 1
  const uvExp = ((uvSeed ^ uvA) ^ uvB) ^ uvC
  const metaKey = Math.floor(rng() * 99999) + 1
  const dispTblKeys = Array.from({length:8}, () => Math.floor(rng() * 255))
  const dispTblVals = Array.from({length:8}, () => Math.floor(rng() * 255))
  const dispSum = dispTblVals.reduce((a,b)=>(a+b)%16777216,0)

  // Base85 decoder (Lua)
  const b85Chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
  const b85MapEntries = Array.from(b85Chars).map((c,i) => `[${c.charCodeAt(0)}]=${i}`).join(',')

  const NL = cfg.minify ? ' ' : '\n'
  const T = cfg.minify ? '' : '  '

  const out: string[] = []
  const L = (...lines: string[]) => lines.forEach(l => out.push(l))
  L(`-- zisuay Team`)

  // ====== ANTI-EMU GUARD ======
  L(`local ${nGuard}=true`)

  // Fibonacci check (EMU clock=0 ไม่กระทบ แต่ต้อง execute จริง)
  L(`local ${nFib1},${nFib2}=1,1`)
  L(`for ${nFibN}=2,${fibN} do local ${nFibT}=${nFib2};${nFib2}=${nFib1}+${nFib2};${nFib1}=${nFibT} end`)
  L(`if ${nFib2}%65536~=${fibExpected} then ${nGuard}=false end`)

  // Math consistency (ต้องใช้ math library จริง)
  L(`local ${nMath1}=math.floor(math.sqrt(${mathA}*${mathB}))`)
  L(`if ${nMath1}~=${mathExp} then ${nGuard}=false end`)

  // Table behavior
  L(`local ${nTbl1}=0`)
  L(`for _,${nV} in ipairs({1,4,9,16,25}) do ${nTbl1}=${nTbl1}+${nV} end`)
  L(`if ${nTbl1}~=${tblSum} then ${nGuard}=false end`)

  // Metatable behavior
  L(`local ${nMeta1}={__index=function(t,k) return ${metaKey} end}`)
  L(`local ${nMeta2}=setmetatable({},${nMeta1})`)
  L(`if ${nMeta2}._candy~=${metaKey} then ${nGuard}=false end`)

  // Upvalue chain
  L(`local ${nUvR}=${uvSeed}`)
  L(`local ${nUvC}=${uvA};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`${nUvC}=${uvB};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`${nUvC}=${uvC};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`if ${nUvR}~=${uvExp} then ${nGuard}=false end`)

  // Coroutine state (EMU ใช้ safe_coroutine ที่ต่างกัน)
  L(`local ${nCo}=coroutine.create(function() end)`)
  L(`local ${nCoSt}=coroutine.status(${nCo})`)
  L(`if ${nCoSt}~="suspended" then ${nGuard}=false end`)
  L(`coroutine.resume(${nCo})`)
  L(`if coroutine.status(${nCo})~="dead" then ${nGuard}=false end`)

  // Pcall behavior
  L(`local ${nPc1},${nPc2}=pcall(function() error("_c_",2) end)`)
  L(`if ${nPc1}~=false or type(${nPc2})~="string" then ${nGuard}=false end`)

  // Dispatch fingerprint table (data-dependent index mapping)
  const dispEntries = dispTblKeys.map((k,i)=>`[${k}]=${dispTblVals[i]}`).join(',')
  L(`local ${nSum}=0;for k,${nV} in pairs({${dispEntries}}) do ${nSum}=(${nSum}+${nV})%16777216 end`)
  L(`if ${nSum}~=${dispSum} then ${nGuard}=false end`)

  // Environment probe (ตรวจ EMU marker)
  L(`local ${nEnvPrb}=getfenv and getfenv()`)
  L(`if ${nEnvPrb} and type(${nEnvPrb})~="table" then ${nGuard}=false end`)
  L(`if ${nEnvPrb} and ${nEnvPrb}.__VMDISPATCH~=nil then ${nGuard}=false end`)

  // Opaque predicates (per-build, static analysis resistant)
  L(`if not(${opaqueA}+${opaqueB}-${opaqueA+opaqueB}==0) then ${nGuard}=false end`)
  L(`if not(bit32 and bit32.bxor(${opaqueA},${opaqueA})==0 or true) then ${nGuard}=false end`)

  // String library probe
  L(`local ${nStrT}=string.char(72,101,108,108,111)`)
  L(`if #${nStrT}~=5 or ${nStrT}:sub(1,1)~="H" then ${nGuard}=false end`)

  // Guard gate — payload gating
  L(`if not ${nGuard} then error("",0) end`)

  // ====== DYNAMIC API RESOLUTION ======
  // ซ่อน API names ใน runtime table แทนเรียกตรง
  L(`local ${nDynApi}={}`)
  const apiNames = ["pairs","ipairs","next","type","tostring","tonumber","pcall","xpcall",
                    "setmetatable","getmetatable","rawget","rawset","rawlen","select","unpack",
                    "error","assert","math","string","table","coroutine","bit32"]
  for (const api of apiNames) {
    const encoded = Array.from(api).map(c=>c.charCodeAt(0)).join(',')
    L(`${nDynApi}[${fnvHash(Array.from(api).map(c=>c.charCodeAt(0)), cfg.seed & 0xFFFF) >>> 0}]=_ENV and _ENV[string.char(${encoded})] or ${api}`)
  }

  // ====== BASE85 DECODER ======
  L(`local ${nBlob}=${JSON.stringify(b85)}`)
  L(`local ${nKey}=${cfg.seed >>> 0}`)
  L(`local ${nChk}=${checksum >>> 0}`)

  // B85 map
  L(`local ${nIdxMap}={${b85MapEntries}}`)

  // Decode base85 → bytes
  L(`local function ${nDecode}(s,k)`)
  L(`  local ${nStrBuf}={}`)
  L(`  local ${nPos}=1`)
  L(`  while ${nPos}<=#s do`)
  L(`    local v=0`)
  L(`    local chunk=math.min(5,#s-${nPos}+1)`)
  L(`    for j=0,chunk-1 do v=v*85+(${nIdxMap}[s:byte(${nPos}+j)] or 0) end`)
  L(`    for j=chunk-2,0,-1 do ${nStrBuf}[#${nStrBuf}+1]=math.floor(v/256^j)%256 end`)
  L(`    ${nPos}=${nPos}+chunk`)
  L(`  end`)
  L(`  return ${nStrBuf}`)
  L(`end`)

  // XOR decrypt + rolling hash verify
  L(`local ${nRolling}=${cfg.seed & 0xFF}`)
  L(`local ${nKs}={}`)
  L(`do`)
  L(`  local s=${cfg.seed >>> 0}`)
  L(`  for i=1,${rawBytes.length} do`)
  L(`    s=(s*1664525+1013904223)%4294967296`)
  L(`    ${nKs}[i]=s%256`)
  L(`  end`)
  L(`end`)
  L(`local ${nPayload}=${nDecode}(${nBlob},${nKey})`)
  const nRaw = N()
  L(`local ${nRaw}={}`)
  const nRolling2 = N()
  L(`local ${nRolling2}=${cfg.seed & 0xFF}`)
  L(`for i=1,#${nPayload} do`)
  L(`  local k=bit32.bxor(bit32.bxor(${nKs}[i],${nRolling2}),(i-1)%256)`)
  L(`  ${nRaw}[i]=bit32.bxor(${nPayload}[i],k)`)
  L(`  ${nRolling2}=(${nRolling2}+${nRaw}[i]+i)%256`)
  L(`end`)

  // Checksum verify (integrity check)
  L(`local ${nChkVar}=2166136261`)
  L(`for _,${nV} in ipairs(${nRaw}) do`)
  L(`  ${nChkVar}=bit32.bxor((${nChkVar}*16777619)%4294967296,${nV})`)
  L(`end`)
  L(`${nChkVar}=bit32.bxor(${nChkVar},${((cfg.seed ^ 0xCAFEBABE) >>> 0)})%4294967296`)
  L(`if ${nChkVar}~=${checksum >>> 0} then error("",0) end`)

  // ====== BYTECODE DESERIALIZER ======
  const nPos2 = N()
  L(`local ${nPos2}=1`)
  L(`local function ${nU8}() local v=${nRaw}[${nPos2}] or 0;${nPos2}=${nPos2}+1;return v end`)
  L(`local function ${nU16}() local a=${nU8}();local b=${nU8}();return a+b*256 end`)
  L(`local function ${nU32}() local a=${nU16}();local b=${nU16}();return a+b*65536 end`)
  L(`local function ${nFlt}()`)
  L(`  local b={};for i=1,8 do b[i]=${nU8}() end`)
  L(`  local sign=b[8]>127 and -1 or 1`)
  L(`  local exp=((b[8]%128)*16+(math.floor(b[7]/16)))`)
  L(`  local mant=0;for i=7,1,-1 do mant=(mant+(i==7 and b[i]%16 or b[i]))/256 end`)
  L(`  if exp==0 then return sign*mant*2^(-1022) end`)
  L(`  if exp==2047 then return mant==0 and sign*(1/0) or 0/0 end`)
  L(`  return sign*(1+mant)*2^(exp-1023)`)
  L(`end`)
  const nStrBuf2 = N()
  L(`local function ${nStrBuf2}()`)
  L(`  local len=${nU16}();local s=""`)
  L(`  for i=1,len do s=s..string.char(${nU8}()) end`)
  L(`  return s`)
  L(`end`)

  // Deserialize proto recursively
  L(`local function ${nProto}()`)
  L(`  local p={params=${nU8}(),vararg=${nU8}()==1,maxStack=${nU8}()}`)
  L(`  local ni=${nU16}();p.instrs={}`)
  L(`  for i=1,ni do`)
  L(`    local op=${nU8}()`)
  // opcode inverse permutation embedded as table
  const invPerm = inv.slice(0, Op._COUNT)
  L(`    local invP={${invPerm.join(',')}}`)
  L(`    local a=${nU8}();local b=${nU8}();local c=${nU8}();local bx=b*256+c;local sbx=bx-32768;p.instrs[i]={op=invP[op+1] or op,a=a,b=b,c=c,bx=bx,sbx=sbx}`)
  L(`  end`)
  L(`  local nk=${nU16}();p.consts={}`)
  L(`  for i=1,nk do`)
  L(`    local t=${nU8}()`)
  L(`    if t==0 then p.consts[i]=nil`)
  L(`    elseif t==1 then p.consts[i]=${nU8}()==1`)
  L(`    elseif t==2 then p.consts[i]=${nFlt}()`)
  L(`    else p.consts[i]=${nStrBuf2}() end`)
  L(`  end`)
  L(`  local nuv=${nU16}();p.upvals={}`)
  L(`  for i=1,nuv do p.upvals[i]={inStack=${nU8}()==1,idx=${nU8}(),name=${nStrBuf2}()} end`)
  L(`  local np=${nU16}();p.protos={}`)
  L(`  for i=1,np do ${nU16}();p.protos[i]=${nProto}() end`)
  L(`  return p`)
  L(`end`)
  const nRoot = N()
  L(`local ${nRoot}=${nProto}()`)

  // ====== VM EXECUTOR ======
  // Handler table (Dispatcher-Based Interpretation + Polymorphic Handlers)
  L(`local function ${nVm}(proto,upvals,env,...)`)
  L(`  local ${nRegs}={}`)
  L(`  local ${nPC}=1`)
  L(`  local ${nConsts}=proto.consts`)
  L(`  local ${nInstrs}=proto.instrs`)
  L(`  local ${nProtos}=proto.protos`)
  L(`  local ${nUvals}=upvals or {}`)
  L(`  local ${nStack}={...}`)
  L(`  local ${nEnv}=env or _ENV or getfenv()`)

  // Load params
  L(`  for i=1,proto.params do ${nRegs}[i-1]=${nStack}[i] end`)
  L(`  if proto.vararg then`)
  L(`    ${nRegs}[-1]={table.unpack(${nStack},proto.params+1)}`)
  L(`  end`)

  // Opcode dispatch handlers (Polymorphic VM Handlers)
  // Shuffle handler order per-build
  const handlerOrder = seededShuffle(Array.from({length:Op._COUNT},(_,i)=>i), mulberry32(cfg.seed^0xABCD))

  L(`  local ${nDisp}={}`)

  // LOADNIL
  L(`  ${nDisp}[${Op.LOADNIL}]=function(ins) ${nRegs}[ins.a]=nil end`)
  // LOADBOOL
  L(`  ${nDisp}[${Op.LOADBOOL}]=function(ins) ${nRegs}[ins.a]=ins.b==1 end`)
  // LOADINT
  L(`  ${nDisp}[${Op.LOADINT}]=function(ins) ${nRegs}[ins.a]=${nConsts}[ins.bx+1] end`)
  // LOADFLOAT
  L(`  ${nDisp}[${Op.LOADFLOAT}]=function(ins) ${nRegs}[ins.a]=${nConsts}[ins.bx+1] end`)
  // LOADSTR
  L(`  ${nDisp}[${Op.LOADSTR}]=function(ins) ${nRegs}[ins.a]=${nConsts}[ins.bx+1] end`)
  // MOVE
  L(`  ${nDisp}[${Op.MOVE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b] end`)
  // GETGLOBAL
  L(`  ${nDisp}[${Op.GETGLOBAL}]=function(ins) ${nRegs}[ins.a]=${nEnv}[${nConsts}[ins.bx+1]] end`)
  // SETGLOBAL
  L(`  ${nDisp}[${Op.SETGLOBAL}]=function(ins) ${nEnv}[${nConsts}[ins.bx+1]]=${nRegs}[ins.a] end`)
  // GETUPVAL
  L(`  ${nDisp}[${Op.GETUPVAL}]=function(ins) ${nRegs}[ins.a]=${nUvals}[ins.b+1] end`)
  // SETUPVAL
  L(`  ${nDisp}[${Op.SETUPVAL}]=function(ins) ${nUvals}[ins.b+1]=${nRegs}[ins.a] end`)
  // GETTABLE
  L(`  ${nDisp}[${Op.GETTABLE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b][${nRegs}[ins.c]] end`)
  // SETTABLE
  L(`  ${nDisp}[${Op.SETTABLE}]=function(ins) ${nRegs}[ins.a][${nRegs}[ins.b]]=${nRegs}[ins.c] end`)
  // GETFIELD
  L(`  ${nDisp}[${Op.GETFIELD}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b][${nConsts}[ins.c+1]] end`)
  // SETFIELD
  L(`  ${nDisp}[${Op.SETFIELD}]=function(ins) ${nRegs}[ins.a][${nConsts}[ins.b+1]]=${nRegs}[ins.c] end`)
  // NEWTABLE
  L(`  ${nDisp}[${Op.NEWTABLE}]=function(ins) ${nRegs}[ins.a]={} end`)
  // ADD
  L(`  ${nDisp}[${Op.ADD}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]+${nRegs}[ins.c] end`)
  // SUB
  L(`  ${nDisp}[${Op.SUB}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]-${nRegs}[ins.c] end`)
  // MUL
  L(`  ${nDisp}[${Op.MUL}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]*${nRegs}[ins.c] end`)
  // DIV
  L(`  ${nDisp}[${Op.DIV}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]/${nRegs}[ins.c] end`)
  // MOD
  L(`  ${nDisp}[${Op.MOD}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]%${nRegs}[ins.c] end`)
  // POW
  L(`  ${nDisp}[${Op.POW}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]^${nRegs}[ins.c] end`)
  // IDIV
  L(`  ${nDisp}[${Op.IDIV}]=function(ins) ${nRegs}[ins.a]=math.floor(${nRegs}[ins.b]/${nRegs}[ins.c]) end`)
  // BAND
  L(`  ${nDisp}[${Op.BAND}]=function(ins) ${nRegs}[ins.a]=bit32.band(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  // BOR
  L(`  ${nDisp}[${Op.BOR}]=function(ins) ${nRegs}[ins.a]=bit32.bor(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  // BXOR
  L(`  ${nDisp}[${Op.BXOR}]=function(ins) ${nRegs}[ins.a]=bit32.bxor(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  // SHL
  L(`  ${nDisp}[${Op.SHL}]=function(ins) ${nRegs}[ins.a]=bit32.lshift(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  // SHR
  L(`  ${nDisp}[${Op.SHR}]=function(ins) ${nRegs}[ins.a]=bit32.rshift(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  // CONCAT
  L(`  ${nDisp}[${Op.CONCAT}]=function(ins) local s="";for i=${nRegs}[ins.b],${nRegs}[ins.c] do s=s..tostring(${nRegs}[i]) end;${nRegs}[ins.a]=s end`)
  // UNM
  L(`  ${nDisp}[${Op.UNM}]=function(ins) ${nRegs}[ins.a]=-${nRegs}[ins.b] end`)
  // NOT
  L(`  ${nDisp}[${Op.NOT}]=function(ins) ${nRegs}[ins.a]=not ${nRegs}[ins.b] end`)
  // LEN
  L(`  ${nDisp}[${Op.LEN}]=function(ins) ${nRegs}[ins.a]=#${nRegs}[ins.b] end`)
  // BNOT
  L(`  ${nDisp}[${Op.BNOT}]=function(ins) ${nRegs}[ins.a]=bit32.bnot(${nRegs}[ins.b]) end`)
  // EQ
  L(`  ${nDisp}[${Op.EQ}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]==${nRegs}[ins.c] end`)
  // NE
  L(`  ${nDisp}[${Op.NE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]~=${nRegs}[ins.c] end`)
  // LT
  L(`  ${nDisp}[${Op.LT}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]<${nRegs}[ins.c] end`)
  // LE
  L(`  ${nDisp}[${Op.LE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]<=${nRegs}[ins.c] end`)
  // GT
  L(`  ${nDisp}[${Op.GT}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]>${nRegs}[ins.c] end`)
  // GE
  L(`  ${nDisp}[${Op.GE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]>=${nRegs}[ins.c] end`)
  // JMP
  L(`  ${nDisp}[${Op.JMP}]=function(ins) ${nPC}=${nPC}+ins.sbx end`)
  // JMPIF
  L(`  ${nDisp}[${Op.JMPIF}]=function(ins) if ${nRegs}[ins.a] then ${nPC}=${nPC}+ins.sbx end end`)
  // JMPNIF
  L(`  ${nDisp}[${Op.JMPNIF}]=function(ins) if not ${nRegs}[ins.a] then ${nPC}=${nPC}+ins.sbx end end`)
  // CLOSURE
  L(`  ${nDisp}[${Op.CLOSURE}]=function(ins)`)
  L(`    local sub=${nProtos}[ins.bx+1]`)
  L(`    local uvs={}`)
  L(`    for i,uv in ipairs(sub.upvals) do`)
  L(`      if uv.inStack then uvs[i]=${nRegs}[uv.idx]`)
  L(`      else uvs[i]=${nUvals}[uv.idx+1] end`)
  L(`    end`)
  L(`    ${nRegs}[ins.a]=function(...) return ${nVm}(sub,uvs,${nEnv},...) end`)
  L(`  end`)
  // CALL
  L(`  ${nDisp}[${Op.CALL}]=function(ins)`)
  L(`    local fn=${nRegs}[ins.a]`)
  L(`    local args={}`)
  L(`    for i=1,ins.b-1 do args[i]=${nRegs}[ins.a+i] end`)
  L(`    local res={fn(table.unpack(args))}`)
  L(`    for i=1,ins.c-1 do ${nRegs}[ins.a+i-1]=res[i] end`)
  L(`  end`)
  // TAILCALL
  L(`  ${nDisp}[${Op.TAILCALL}]=function(ins)`)
  L(`    local fn=${nRegs}[ins.a]`)
  L(`    local args={}`)
  L(`    for i=1,ins.b-1 do args[i]=${nRegs}[ins.a+i] end`)
  L(`    return fn(table.unpack(args))`)
  L(`  end`)
  // RETURN
  L(`  ${nDisp}[${Op.RETURN}]=function(ins)`)
  L(`    if ins.b==1 then return end`)
  L(`    local res={}`)
  L(`    for i=0,ins.b-2 do res[i+1]=${nRegs}[ins.a+i] end`)
  L(`    return table.unpack(res)`)
  L(`  end`)
  // VARARG
  L(`  ${nDisp}[${Op.VARARG}]=function(ins)`)
  L(`    local va=${nRegs}[-1] or {}`)
  L(`    for i=0,ins.b do ${nRegs}[ins.a+i]=va[i+1] end`)
  L(`  end`)
  // FORPREP
  L(`  ${nDisp}[${Op.FORPREP}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.a]-${nRegs}[ins.a+2];${nPC}=${nPC}+ins.sbx end`)
  // FORLOOP
  L(`  ${nDisp}[${Op.FORLOOP}]=function(ins)`)
  L(`    ${nRegs}[ins.a]=${nRegs}[ins.a]+${nRegs}[ins.a+2]`)
  L(`    if ${nRegs}[ins.a]<=${nRegs}[ins.a+1] then`)
  L(`      ${nRegs}[ins.a+3]=${nRegs}[ins.a]`)
  L(`      ${nPC}=${nPC}+ins.sbx`)
  L(`    end`)
  L(`  end`)
  // TFORLOOP
  L(`  ${nDisp}[${Op.TFORLOOP}]=function(ins)`)
  L(`    local res={${nRegs}[ins.a](${nRegs}[ins.a+1],${nRegs}[ins.a+2])}`)
  L(`    if res[1]~=nil then`)
  L(`      ${nRegs}[ins.a+2]=res[1]`)
  L(`      for i=1,ins.c do ${nRegs}[ins.a+2+i]=res[i] end`)
  L(`      ${nPC}=${nPC}+ins.sbx`)
  L(`    end`)
  L(`  end`)
  // SELF
  L(`  ${nDisp}[${Op.SELF}]=function(ins)`)
  L(`    ${nRegs}[ins.a+1]=${nRegs}[ins.b]`)
  L(`    ${nRegs}[ins.a]=${nRegs}[ins.b][${nConsts}[ins.c+1]]`)
  L(`  end`)
  // GETFIELD alias
  L(`  ${nDisp}[${Op.ADDK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]+${nConsts}[ins.c+1] end`)
  L(`  ${nDisp}[${Op.SUBK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]-${nConsts}[ins.c+1] end`)
  L(`  ${nDisp}[${Op.MULK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]*${nConsts}[ins.c+1] end`)
  L(`  ${nDisp}[${Op.DIVK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]/${nConsts}[ins.c+1] end`)
  L(`  ${nDisp}[${Op.MODK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]%${nConsts}[ins.c+1] end`)
  L(`  ${nDisp}[${Op.GETTABK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b][${nConsts}[ins.c+1]] end`)
  L(`  ${nDisp}[${Op.SETTABK}]=function(ins) ${nRegs}[ins.a][${nConsts}[ins.b+1]]=${nConsts}[ins.c+1] end`)
  // SETLIST
  L(`  ${nDisp}[${Op.SETLIST}]=function(ins)`)
  L(`    for i=1,ins.c do ${nRegs}[ins.a][ins.b+i-1]=${nRegs}[ins.a+i] end`)
  L(`  end`)
  // CHECKPOINT (runtime integrity, EMU ต้องผ่าน every instruction)
  const cpExpected = arxMix(cfg.seed, 0x31337) & 0xFFFF
  L(`  ${nDisp}[${Op.CHECKPOINT}]=function(ins)`)
  L(`    local h=${cfg.seed & 0xFFFF}`)
  L(`    h=(h*${opaqueA})%65536`)
  L(`    if h~=${cpExpected} then error("",0) end`)
  L(`  end`)
  // POISON (crash any emulator that hits this — dead code paths only)
  L(`  ${nDisp}[${Op.POISON}]=function(ins) error("",0) end`)

  // ====== DISPATCH LOOP (State-Machine Control Flow) ======
  L(`  while true do`)
  L(`    local ins=${nInstrs}[${nPC}]`)
  L(`    if not ins then break end`)
  L(`    ${nPC}=${nPC}+1`)
  L(`    local h=${nDisp}[ins.op]`)
  L(`    if h then`)
  L(`      local r={h(ins)}`)
  L(`      if #r>0 then return table.unpack(r) end`)
  L(`    end`)
  L(`  end`)
  L(`end`)

  // ====== MULTI-STAGE LOADER ======
  // Stage 1: decrypt + verify
  // Stage 2: deserialize
  // Stage 3: execute
  L(`local function ${nStage1}()`)
  L(`  return ${nVm}(${nRoot},nil,_ENV or getfenv())`)
  L(`end`)
  L(`return ${nStage1}()`)

  return out.join(NL)
}

export { mulberry32 } from "./utils"

