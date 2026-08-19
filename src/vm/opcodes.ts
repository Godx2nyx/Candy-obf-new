// ============================================================
//  Candy-obf-new  |  Opcodes
//  Custom instruction set + per-build opcode permutation
// ============================================================

// ── Base opcode enum (fixed, never exposed in output) ────────
export const enum Op {
  // ── Register / constant loading ──────────────────────────
  MOVE        = 0,   // R(A) = R(B)
  LOADK       = 1,   // R(A) = K(Bx)
  LOADBOOL    = 2,   // R(A) = (bool)B;  if C: pc++
  LOADNIL     = 3,   // R(A..B) = nil

  // ── Upvalue ops ──────────────────────────────────────────
  GETUPVAL    = 4,   // R(A) = UpVal[B]
  SETUPVAL    = 5,   // UpVal[B] = R(A)
  GETTABUP    = 6,   // R(A) = UpVal[B][RK(C)]
  SETTABUP    = 7,   // UpVal[A][RK(B)] = RK(C)

  // ── Table ops ────────────────────────────────────────────
  GETTABLE    = 8,   // R(A) = R(B)[RK(C)]
  SETTABLE    = 9,   // R(A)[RK(B)] = RK(C)
  NEWTABLE    = 10,  // R(A) = {}
  SELF        = 11,  // R(A+1)=R(B); R(A)=R(B)[RK(C)]
  SETLIST     = 12,  // R(A)[C*FPF+i] = R(A+i), i=1..B

  // ── Arithmetic ───────────────────────────────────────────
  ADD         = 13,  // R(A) = RK(B) + RK(C)
  SUB         = 14,  // R(A) = RK(B) - RK(C)
  MUL         = 15,  // R(A) = RK(B) * RK(C)
  DIV         = 16,  // R(A) = RK(B) / RK(C)
  MOD         = 17,  // R(A) = RK(B) % RK(C)
  POW         = 18,  // R(A) = RK(B) ^ RK(C)
  IDIV        = 19,  // R(A) = RK(B) // RK(C)

  // ── Bitwise (Luau/Lua5.3+) ───────────────────────────────
  BAND        = 20,  // R(A) = RK(B) & RK(C)
  BOR         = 21,  // R(A) = RK(B) | RK(C)
  BXOR        = 22,  // R(A) = RK(B) ~ RK(C)
  SHL         = 23,  // R(A) = RK(B) << RK(C)
  SHR         = 24,  // R(A) = RK(B) >> RK(C)

  // ── Unary ────────────────────────────────────────────────
  UNM         = 25,  // R(A) = -R(B)
  BNOT        = 26,  // R(A) = ~R(B)
  NOT         = 27,  // R(A) = not R(B)
  LEN         = 28,  // R(A) = #R(B)

  // ── String ───────────────────────────────────────────────
  CONCAT      = 29,  // R(A) = R(B)..…..R(C)

  // ── Control flow ─────────────────────────────────────────
  JMP         = 30,  // pc += sBx  [+close upvals A..top]
  EQ          = 31,  // if (RK(B)==RK(C)) ~= A  then pc++
  LT          = 32,  // if (RK(B)<RK(C))  ~= A  then pc++
  LE          = 33,  // if (RK(B)<=RK(C)) ~= A  then pc++
  TEST        = 34,  // if not (R(A) <=> C)      then pc++
  TESTSET     = 35,  // if (R(B) <=> C) R(A)=R(B) else pc++

  // ── Calls ────────────────────────────────────────────────
  CALL        = 36,  // R(A)…R(A+C-2) = R(A)(R(A+1)…R(A+B-1))
  TAILCALL    = 37,  // return R(A)(R(A+1)…R(A+B-1))
  RETURN      = 38,  // return R(A)…R(A+B-2)

  // ── Loops ────────────────────────────────────────────────
  FORLOOP     = 39,  // numeric for step
  FORPREP     = 40,  // numeric for prep
  TFORCALL    = 41,  // generic for call
  TFORLOOP    = 42,  // generic for step

  // ── Closures / misc ──────────────────────────────────────
  CLOSURE     = 43,  // R(A) = closure(Proto[Bx])
  VARARG      = 44,  // R(A)…R(A+B-1) = vararg
  CLOSE       = 45,  // close upvalues ≥ R(A)

  // ── Global access (Luau compat) ──────────────────────────
  GETGLOBAL   = 46,  // R(A) = Gbl[K(Bx)]
  SETGLOBAL   = 47,  // Gbl[K(Bx)] = R(A)

  __COUNT     = 48,
}

// ── Fisher-Yates shuffle driven by xoshiro128** ──────────────
function xoshiro128(s: [number, number, number, number]) {
  return (): number => {
    const result = Math.imul(s[1], 5);
    const r = ((result << 7) | (result >>> 25)) >>> 0;
    const t = (s[1] << 9) >>> 0;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t;
    s[3] = ((s[3] << 11) | (s[3] >>> 21)) >>> 0;
    return r;
  };
}

/**
 * Generate a per-build opcode permutation table.
 *
 * Returns `opcodeMap` where `opcodeMap[baseOp]` = the scrambled byte
 * value that will appear in the encrypted bytecode stream.
 * The inverse (scrambled → base) is embedded in the generated Luau VM.
 */
export function generateOpcodeMap(
  seed: [number, number, number, number]
): number[] {
  const rng  = xoshiro128([...seed] as [number,number,number,number]);
  const perm = Array.from({ length: Op.__COUNT }, (_, i) => i);

  // Fisher-Yates
  for (let i = perm.length - 1; i > 0; i--) {
    const j = rng() % (i + 1);
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }

  // perm[i] = scrambled value for base opcode i
  return perm;
}

/** Invert the opcode map: scrambled → base */
export function invertOpcodeMap(opcodeMap: number[]): number[] {
  const inv = new Array<number>(Op.__COUNT);
  for (let i = 0; i < Op.__COUNT; i++) inv[opcodeMap[i]] = i;
  return inv;
}

/** Human-readable opcode name (for debug/emit) */
export const OP_NAMES: Record<number, string> = {
  [Op.MOVE]:      "MOVE",
  [Op.LOADK]:     "LOADK",
  [Op.LOADBOOL]:  "LOADBOOL",
  [Op.LOADNIL]:   "LOADNIL",
  [Op.GETUPVAL]:  "GETUPVAL",
  [Op.SETUPVAL]:  "SETUPVAL",
  [Op.GETTABUP]:  "GETTABUP",
  [Op.SETTABUP]:  "SETTABUP",
  [Op.GETTABLE]:  "GETTABLE",
  [Op.SETTABLE]:  "SETTABLE",
  [Op.NEWTABLE]:  "NEWTABLE",
  [Op.SELF]:      "SELF",
  [Op.SETLIST]:   "SETLIST",
  [Op.ADD]:       "ADD",
  [Op.SUB]:       "SUB",
  [Op.MUL]:       "MUL",
  [Op.DIV]:       "DIV",
  [Op.MOD]:       "MOD",
  [Op.POW]:       "POW",
  [Op.IDIV]:      "IDIV",
  [Op.BAND]:      "BAND",
  [Op.BOR]:       "BOR",
  [Op.BXOR]:      "BXOR",
  [Op.SHL]:       "SHL",
  [Op.SHR]:       "SHR",
  [Op.UNM]:       "UNM",
  [Op.BNOT]:      "BNOT",
  [Op.NOT]:       "NOT",
  [Op.LEN]:       "LEN",
  [Op.CONCAT]:    "CONCAT",
  [Op.JMP]:       "JMP",
  [Op.EQ]:        "EQ",
  [Op.LT]:        "LT",
  [Op.LE]:        "LE",
  [Op.TEST]:      "TEST",
  [Op.TESTSET]:   "TESTSET",
  [Op.CALL]:      "CALL",
  [Op.TAILCALL]:  "TAILCALL",
  [Op.RETURN]:    "RETURN",
  [Op.FORLOOP]:   "FORLOOP",
  [Op.FORPREP]:   "FORPREP",
  [Op.TFORCALL]:  "TFORCALL",
  [Op.TFORLOOP]:  "TFORLOOP",
  [Op.CLOSURE]:   "CLOSURE",
  [Op.VARARG]:    "VARARG",
  [Op.CLOSE]:     "CLOSE",
  [Op.GETGLOBAL]: "GETGLOBAL",
  [Op.SETGLOBAL]: "SETGLOBAL",
};
