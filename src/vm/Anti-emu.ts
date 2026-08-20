import { mulberry32 } from "./utils"

export interface AntiEmuConfig {
  seed: number
  guardVarName: string
  checksumVarName: string
}

// ====== TECHNIQUE 1: MATH CONSISTENCY ======
// EMU ไม่ได้ implement math ครบ ใช้ค่าที่ต้องคำนวณจริงๆ
export function genMathConsistencyCheck(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0xCAFE)
  const a = 1 + Math.floor(rng() * 9999)
  const b = 1 + Math.floor(rng() * 9999)
  const expected = Math.floor(Math.sqrt(a * b))
  const v1 = `_v${Math.floor(rng() * 9999)}`
  const v2 = `_v${Math.floor(rng() * 9999)}`
  return [
    `local ${v1}=math.floor(math.sqrt(${a}*${b}))`,
    `local ${v2}=${expected}`,
    `if ${v1}~=${v2} then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== TECHNIQUE 2: STRING BEHAVIOR ======
// EMU อาจไม่ implement string library ครบถ้วน
export function genStringConsistencyCheck(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0xBEEF)
  const testStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  const idx = 1 + Math.floor(rng() * 10)
  const len = 1 + Math.floor(rng() * 5)
  const expected = testStr.slice(idx - 1, idx - 1 + len)
  const encodedStr = Array.from(testStr).map(c => c.charCodeAt(0)).join(",")
  const v1 = `_sv${Math.floor(rng() * 9999)}`
  const v2 = `_sv${Math.floor(rng() * 9999)}`
  return [
    `local ${v1}=string.char(${Array.from(testStr).slice(0,8).map(c=>c.charCodeAt(0)).join(",")})`,
    `local ${v2}=${v1}:sub(${idx},${idx+len-1})`,
    `if ${v2}~=${JSON.stringify(expected)} then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== TECHNIQUE 3: PCALL BEHAVIOR ======
// EMU มักจัดการ pcall ไม่ตรง spec
export function genPcallBehaviorCheck(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0xDEAD)
  const errMsg = `_err${Math.floor(rng() * 9999)}`
  const okVar = `_ok${Math.floor(rng() * 9999)}`
  return [
    `local ${okVar},${errMsg}=pcall(function() error("_candy_test_",2) end)`,
    `if ${okVar}~=false then ${cfg.guardVarName}=false end`,
    `if type(${errMsg})~="string" then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== TECHNIQUE 4: TABLE BEHAVIOR ======
// next() iteration order ต้องสม่ำเสมอ
export function genTableBehaviorCheck(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0xFACE)
  const tVar = `_t${Math.floor(rng() * 9999)}`
  const cVar = `_c${Math.floor(rng() * 9999)}`
  return [
    `local ${tVar}={${Array.from({length:5},(_,i)=>`[${i+1}]=${i*i+1}`).join(",")}}`,
    `local ${cVar}=0`,
    `for _,v in ipairs(${tVar}) do ${cVar}=${cVar}+v end`,
    `if ${cVar}~=${[0,1,2,3,4].map(i=>i*i+1).reduce((a,b)=>a+b,0)} then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== TECHNIQUE 5: METATABLE BEHAVIOR ======
// EMU ที่ไม่ implement metatable ครบจะ fail
export function genMetatableCheck(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0xACE)
  const tVar = `_mt${Math.floor(rng() * 9999)}`
  const objVar = `_obj${Math.floor(rng() * 9999)}`
  const resVar = `_res${Math.floor(rng() * 9999)}`
  const expected = Math.floor(rng() * 9999) + 1
  return [
    `local ${tVar}={__index=function(t,k) return ${expected} end}`,
    `local ${objVar}=setmetatable({},${tVar})`,
    `local ${resVar}=${objVar}._candy_key`,
    `if ${resVar}~=${expected} then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== TECHNIQUE 6: UPVALUE CHAIN TRAP ======
// สร้าง upvalue chain ที่ EMU ต้องเดินตามทุก level
export function genUpvalueChainCheck(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0x1234)
  const seed = Math.floor(rng() * 0xFFFF)
  const depth = 3 + Math.floor(rng() * 3)
  const vars = Array.from({length: depth}, (_, i) => `_uv${i}_${Math.floor(rng()*999)}`)
  const vals = Array.from({length: depth}, () => Math.floor(rng() * 255) + 1)
  const expected = vals.reduce((a, b) => (a ^ b) & 0xFFFF, seed)
  const resultVar = `_ur${Math.floor(rng() * 9999)}`

  const lines: string[] = [`local ${resultVar}=${seed}`]
  for (let i = 0; i < depth; i++) {
    lines.push(`local ${vars[i]}=${vals[i]}`)
    lines.push(`${resultVar}=(function() return ${resultVar}~${vars[i]} end)()`)
  }
  lines.push(`if ${resultVar}~=${expected} then ${cfg.guardVarName}=false end`)
  return lines.join(";")
}

// ====== TECHNIQUE 7: COROUTINE STATE ======
// EMU ใน run_goofy ใช้ safe_coroutine ที่ต่างจาก real coroutine
export function genCoroutineCheck(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0x5678)
  const coVar = `_co${Math.floor(rng() * 9999)}`
  const stVar = `_cst${Math.floor(rng() * 9999)}`
  return [
    `local ${coVar}=coroutine.create(function() end)`,
    `local ${stVar}=coroutine.status(${coVar})`,
    `if ${stVar}~="suspended" then ${cfg.guardVarName}=false end`,
    `coroutine.resume(${coVar})`,
    `if coroutine.status(${coVar})~="dead" then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== TECHNIQUE 8: DISPATCH FINGERPRINT ======
// สร้าง dispatch ที่ EMU จะวิเคราะห์ได้ยาก
// ใช้ table ที่ index ด้วย runtime value
export function genDispatchFingerprint(cfg: AntiEmuConfig, dispatchVar: string): string {
  const rng = mulberry32(cfg.seed ^ 0x9ABC)
  const n = 8 + Math.floor(rng() * 8)
  const indices = Array.from({length: n}, () => Math.floor(rng() * 256))
  const values = Array.from({length: n}, () => Math.floor(rng() * 256))

  // สร้าง checksum จาก runtime dispatch
  const tableEntries = indices.map((k, i) => `[${k}]=${values[i]}`).join(",")
  const expectedSum = values.reduce((a, b) => (a + b) & 0xFFFFFF, 0)
  const sumVar = `_ds${Math.floor(rng() * 9999)}`
  const tVar = `_dt${Math.floor(rng() * 9999)}`

  return [
    `local ${tVar}={${tableEntries}}`,
    `local ${sumVar}=0`,
    `for k,v in pairs(${tVar}) do ${sumVar}=(${sumVar}+v)%16777216 end`,
    `if ${sumVar}~=${expectedSum} then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== TECHNIQUE 9: FIBONACCI CHECKSUM ======
// คำนวณ Fibonacci ที่ EMU ต้องใช้ CPU จริง
// EMU ที่ throttle instruction จะได้ผลต่างออก
export function genFibonacciChecksum(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0xF1B0)
  const n = 15 + Math.floor(rng() * 10)
  let a = 1, b = 1
  for (let i = 2; i < n; i++) { [a, b] = [b, a + b] }
  const expected = b % 65536
  const aVar = `_fa${Math.floor(rng() * 9999)}`
  const bVar = `_fb${Math.floor(rng() * 9999)}`
  const iVar = `_fi${Math.floor(rng() * 9999)}`
  const tVar = `_ft${Math.floor(rng() * 9999)}`
  return [
    `local ${aVar},${bVar}=1,1`,
    `for ${iVar}=2,${n} do local ${tVar}=${bVar};${bVar}=${aVar}+${bVar};${aVar}=${tVar} end`,
    `if ${bVar}%65536~=${expected} then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== TECHNIQUE 10: ENVIRONMENT PROBE ======
// ตรวจว่า environment มีสิ่งที่ EMU inject ไว้หรือเปล่า
export function genEnvironmentProbe(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0xE0E0)
  const probeVar = `_ep${Math.floor(rng() * 9999)}`
  // EMU มักใส่ __VMDISPATCH หรือ __proto_labels ไว้ใน env
  return [
    // ตรวจว่า getfenv() ส่งคืน table จริงๆ
    `local ${probeVar}=getfenv and getfenv()`,
    `if ${probeVar} and type(${probeVar})~="table" then ${cfg.guardVarName}=false end`,
    // ตรวจว่าไม่มี __VMDISPATCH (EMU marker)
    `if ${probeVar} and ${probeVar}.__VMDISPATCH~=nil then ${cfg.guardVarName}=false end`,
    `if ${probeVar} and ${probeVar}.__proto_labels~=nil then ${cfg.guardVarName}=false end`
  ].join(";")
}

// ====== COMBINE ALL CHECKS ======
export function generateAntiEmuChecks(cfg: AntiEmuConfig): string {
  const rng = mulberry32(cfg.seed ^ 0x1337)
  const checks = [
    genMathConsistencyCheck(cfg),
    genStringConsistencyCheck(cfg),
    genPcallBehaviorCheck(cfg),
    genTableBehaviorCheck(cfg),
    genMetatableCheck(cfg),
    genUpvalueChainCheck(cfg),
    genCoroutineCheck(cfg),
    genFibonacciChecksum(cfg),
    genEnvironmentProbe(cfg),
  ]

  // สลับลำดับ checks ตาม seed (ทำให้ static analysis ยากขึ้น)
  for (let i = checks.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1))
    ;[checks[i], checks[j]] = [checks[j], checks[i]]
  }

  return [
    `local ${cfg.guardVarName}=true`,
    ...checks,
    `if not ${cfg.guardVarName} then`,
    `  error("_candy_guard_",0)`,
    `end`
  ].join("\n")
}

