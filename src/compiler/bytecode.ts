// ====== INSTRUCTION SET ======
export const enum Op {
  // Load constants
  LOADNIL,    // R[A] = nil
  LOADBOOL,   // R[A] = bool(B)
  LOADINT,    // R[A] = C (integer constant)
  LOADFLOAT,  // R[A] = K[Bx] (float constant)
  LOADSTR,    // R[A] = K[Bx] (string constant)

  // Variable ops
  MOVE,       // R[A] = R[B]
  GETGLOBAL,  // R[A] = ENV[K[Bx]]
  SETGLOBAL,  // ENV[K[Bx]] = R[A]
  GETUPVAL,   // R[A] = UP[B]
  SETUPVAL,   // UP[B] = R[A]
  GETTABLE,   // R[A] = R[B][R[C]]
  SETTABLE,   // R[A][R[B]] = R[C]
  GETFIELD,   // R[A] = R[B][K[C]]
  SETFIELD,   // R[A][K[B]] = R[C]
  NEWTABLE,   // R[A] = {} (size B)
  SETLIST,    // R[A][B..B+C] = R[A+1..A+1+C]

  // Arithmetic
  ADD,        // R[A] = R[B] + R[C]
  SUB,        // R[A] = R[B] - R[C]
  MUL,        // R[A] = R[B] * R[C]
  DIV,        // R[A] = R[B] / R[C]
  MOD,        // R[A] = R[B] % R[C]
  POW,        // R[A] = R[B] ^ R[C]
  IDIV,       // R[A] = R[B] // R[C]
  BAND,       // R[A] = R[B] & R[C]
  BOR,        // R[A] = R[B] | R[C]
  BXOR,       // R[A] = R[B] ~ R[C]
  SHL,        // R[A] = R[B] << R[C]
  SHR,        // R[A] = R[B] >> R[C]
  CONCAT,     // R[A] = R[B] .. R[B+1] .. ... .. R[C]

  // Unary
  UNM,        // R[A] = -R[B]
  NOT,        // R[A] = not R[B]
  LEN,        // R[A] = #R[B]
  BNOT,       // R[A] = ~R[B]

  // Comparison (if false, skip next)
  EQ,         // R[B] == R[C]
  NE,         // R[B] ~= R[C]
  LT,         // R[B] < R[C]
  LE,         // R[B] <= R[C]
  GT,         // R[B] > R[C]
  GE,         // R[B] >= R[C]

  // Jump
  JMP,        // PC += Bx
  JMPIF,      // if R[A] then PC += Bx
  JMPNIF,     // if not R[A] then PC += Bx

  // Function
  CLOSURE,    // R[A] = closure(K[Bx])
  CALL,       // R[A..A+C] = R[A](R[A+1..A+B])
  TAILCALL,   // return R[A](R[A+1..A+B])
  RETURN,     // return R[A..A+B-1]
  VARARG,     // R[A..A+B] = vararg

  // Loop
  FORPREP,    // R[A] -= R[A+2]; PC += Bx
  FORLOOP,    // R[A] += R[A+2]; if R[A] <= R[A+1] then PC += Bx; R[A+3] = R[A]
  TFORLOOP,   // if R[A+2] ~= nil then R[A+2+i] = R[A+3+i]; PC += Bx

  // Self
  SELF,       // R[A+1]=R[B]; R[A]=R[B][K[C]]

  // Const ops (K version)
  ADDK,       // R[A] = R[B] + K[C]
  SUBK,       // R[A] = R[B] - K[C]
  MULK,       // R[A] = R[B] * K[C]
  DIVK,       // R[A] = R[B] / K[C]
  MODK,       // R[A] = R[B] % K[C]

  // Table
  GETTABK,    // R[A] = R[B][K[C]] (index by const)
  SETTABK,    // R[A][K[B]] = K[C]

  // EMU-resistance
  CHECKPOINT, // verify runtime state hash
  POISON,     // invalid op — crash emulators that don't handle it

  _COUNT
}

export interface Instruction {
  op: Op
  a: number
  b: number
  c: number
  bx: number   // b << 8 | c (16-bit)
  sbx: number  // signed bx
  line: number
}

export function makeInstr(op: Op, a: number, b: number, c: number, line = 0): Instruction {
  return { op, a, b, c, bx: (b << 8) | c, sbx: 0, line }
}

export function makeInstrBx(op: Op, a: number, bx: number, line = 0): Instruction {
  return { op, a, b: (bx >> 8) & 0xFF, c: bx & 0xFF, bx, sbx: bx - 0x8000, line }
}

export function makeInstrSBx(op: Op, a: number, sbx: number, line = 0): Instruction {
  const bx = sbx + 0x8000
  return { op, a, b: (bx >> 8) & 0xFF, c: bx & 0xFF, bx, sbx, line }
}

// ====== CONSTANT POOL ======
export type Constant =
  | { type: "nil" }
  | { type: "boolean"; value: boolean }
  | { type: "number"; value: number }
  | { type: "string"; value: string }

export function constNil(): Constant { return { type: "nil" } }
export function constBool(v: boolean): Constant { return { type: "boolean", value: v } }
export function constNum(v: number): Constant { return { type: "number", value: v } }
export function constStr(v: string): Constant { return { type: "string", value: v } }

// ====== PROTO (function prototype) ======
export interface Proto {
  id: number
  params: number
  hasVarArg: boolean
  maxStack: number
  instructions: Instruction[]
  constants: Constant[]
  protos: Proto[]        // nested functions
  upvalues: UpvalDesc[]
  lineInfo: number[]
}

export interface UpvalDesc {
  name: string
  inStack: boolean       // true = register, false = upvalue of parent
  idx: number
}

export function createProto(id: number, params: number, hasVarArg: boolean): Proto {
  return {
    id, params, hasVarArg,
    maxStack: params + 1,
    instructions: [],
    constants: [],
    protos: [],
    upvalues: [],
    lineInfo: []
  }
}

