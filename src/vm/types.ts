// ============================================================
//  Candy-obf-new  |  VM Types
//  Register-based Luau virtual machine type definitions
// ============================================================

export type LuauValue =
  | null           // nil
  | boolean
  | number
  | string
  | LuauProto      // function prototype reference

// ── Instruction layout ──────────────────────────────────────
// Each instruction: 32-bit word
//   bits  0– 5 : OP  (6 bits,  0–63)
//   bits  6–13 : A   (8 bits,  0–255)
//   bits 14–22 : B   (9 bits,  0–511)
//   bits 23–31 : C   (9 bits,  0–511)
//   Bx  = B << 9 | C        (18-bit unsigned)
//   sBx = Bx - MAXARG_sBx   (18-bit signed, bias = 131071)
export interface Instruction {
  op:  number;   // base opcode  (before permutation)
  A:   number;
  B:   number;
  C:   number;
  Bx:  number;
  sBx: number;
}

// ── Upvalue descriptor ───────────────────────────────────────
export interface UpvalDesc {
  instack: boolean;  // true = lives in enclosing register file
  idx:     number;   // register index (instack) or upval index (!instack)
  name?:   string;
}

// ── Function prototype ───────────────────────────────────────
export interface LuauProto {
  code:         Instruction[];
  constants:    LuauValue[];
  protos:       LuauProto[];    // nested function prototypes
  upvals:       UpvalDesc[];
  maxStackSize: number;
  numParams:    number;
  isVararg:     boolean;
  name?:        string;
}

// ── Encoded bytecode payload ─────────────────────────────────
export interface EncodedPayload {
  bytes: number[];   // XOR-encrypted bytecode
  hash:  number;     // FNV-1a integrity hash of plaintext
}

// ── Per-build VM configuration ───────────────────────────────
export interface VMConfig {
  /** 128-bit xoshiro128** seed  (4 × u32) */
  seed: [number, number, number, number];

  /** Permuted opcode values: opcodeMap[baseOp] = scrambledByte */
  opcodeMap: number[];

  /** Seeded key for constant/string XOR encryption */
  stringKey: number;

  /** Expected FNV-1a hash of the unencrypted proto dump */
  integrityHash: number;

  antiEmu: boolean;

  /** Wrap payload in a multi-stage loader shell */
  multiStage: boolean;

  /** Base-85 armour the encoded bytes */
  base85: boolean;

  /** Emit anti-tamper closure/hook detection */
  antiTamper: boolean;

  /** Inject opaque predicates to resist static analysis */
  opaquePredicates: boolean;

  /** Number of junk code passes injected into dispatch loop */
  junkPasses: number;
}

// ── Serialised proto (binary layout, before XOR) ─────────────
// Layout written by ProtoSerializer:
//   [numParams u8][isVararg u8][maxStack u8][numConsts u16 LE]
//   constants:
//     [type u8]
//       0 = nil    (no payload)
//       1 = bool   [value u8]
//       2 = number [f64 LE × 8 bytes]
//       3 = string [len u16 LE] [bytes…]
//   [numInstrs u16 LE]
//   instructions: [A u8][B u16 LE][C u16 LE][op u8]  × numInstrs
//   [numProtos u8]
//   sub-protos: (recursive)
//   [numUpvals u8]
//   upvals: [instack u8][idx u8]  × numUpvals
export interface SerializedProto {
  bytes: Uint8Array;
}
