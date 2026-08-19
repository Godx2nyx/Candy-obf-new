// ============================================================
//  Candy-obf-new  |  Encoder
//  ARX mixer · XOR stream · Base-85 armour · FNV-1a hash
//  Proto serializer  ·  Constant encryption
// ============================================================

import { LuauProto, LuauValue, EncodedPayload } from "./types";
import { Op } from "./opcodes";

// ── u32 helpers ──────────────────────────────────────────────
const u32 = (n: number) => n >>> 0;
const rotl = (x: number, k: number) => u32((x << k) | (x >>> (32 - k)));

// ── xoshiro128** (same as opcodes.ts, self-contained) ────────
function makeRng(seed: [number, number, number, number]) {
  const s = [...seed] as [number, number, number, number];
  return () => {
    const r = u32(rotl(u32(Math.imul(s[1], 5)), 7) * 9);
    const t = u32(s[1] << 9);
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 11);
    return r;
  };
}

// ── Custom 32-bit ARX mixer (Stateful Rolling Hash) ──────────
// Used to derive per-byte XOR keys from the seed.
// Rounds: XOR-fold, multiplicative mix (modulo 2^32), rotate.
export class ArxMixer {
  private state: number;
  constructor(seed: number) {
    // Seeded key schedule
    this.state = u32(seed ^ 0xDEADBEEF);
    for (let i = 0; i < 8; i++) this.next();
  }

  next(): number {
    let s = this.state;
    s = u32(s ^ (s >>> 16));
    s = u32(Math.imul(s, 0x45D9F3B));
    s = u32(s ^ (s >>> 16));
    s = u32(Math.imul(s, 0xBF5916A7));
    s = u32(s ^ (s >>> 16));
    this.state = s;
    return s;
  }

  /** Get next XOR byte (0–255) */
  nextByte(): number {
    return this.next() & 0xFF;
  }
}

// ── FNV-1a hash (Stateful Rolling Accumulator) ──────────────
export function fnv1a(bytes: number[]): number {
  let h = u32(0x811C9DC5);
  for (const b of bytes) {
    h = u32(h ^ b);
    h = u32(Math.imul(h, 0x01000193));
  }
  return h;
}

// ── Proto serialiser ─────────────────────────────────────────
// Writes a LuauProto into a flat byte array (plaintext).
export function serializeProto(
  proto: LuauProto,
  opcodeMap: number[]
): number[] {
  const buf: number[] = [];

  const writeU8  = (v: number) => buf.push(v & 0xFF);
  const writeU16 = (v: number) => { buf.push(v & 0xFF); buf.push((v >> 8) & 0xFF); };
  const writeU32 = (v: number) => {
    buf.push(v & 0xFF); buf.push((v >> 8) & 0xFF);
    buf.push((v >> 16) & 0xFF); buf.push((v >> 24) & 0xFF);
  };
  const writeF64 = (v: number) => {
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, v, true);
    for (let i = 0; i < 8; i++) buf.push(view.getUint8(i));
  };
  const writeStr = (s: string) => {
    const enc = new TextEncoder().encode(s);
    writeU16(enc.length);
    for (const b of enc) buf.push(b);
  };

  function writeProto(p: LuauProto) {
    writeU8(p.numParams);
    writeU8(p.isVararg ? 1 : 0);
    writeU8(p.maxStackSize);

    // Constants
    writeU16(p.constants.length);
    for (const k of p.constants) {
      if (k === null) {
        writeU8(0);
      } else if (typeof k === "boolean") {
        writeU8(1);
        writeU8(k ? 1 : 0);
      } else if (typeof k === "number") {
        writeU8(2);
        writeF64(k);
      } else if (typeof k === "string") {
        writeU8(3);
        writeStr(k);
      } else {
        // Nested proto reference (index into protos array)
        writeU8(4);
        writeU16(p.protos.indexOf(k));
      }
    }

    // Instructions  (op is remapped through opcodeMap)
    writeU16(p.code.length);
    for (const instr of p.code) {
      writeU8(instr.A & 0xFF);
      writeU16(instr.B & 0x1FF);
      writeU16(instr.C & 0x1FF);
      // Write permuted opcode — this is what lives in the bytecode
      writeU8(opcodeMap[instr.op] & 0xFF);
    }

    // Sub-protos (recursive)
    writeU8(p.protos.length);
    for (const sub of p.protos) writeProto(sub);

    // Upvalue descriptors
    writeU8(p.upvals.length);
    for (const uv of p.upvals) {
      writeU8(uv.instack ? 1 : 0);
      writeU8(uv.idx & 0xFF);
    }
  }

  writeProto(proto);
  return buf;
}

// ── XOR stream encryption ────────────────────────────────────
export function encryptBytes(
  plain: number[],
  seed: [number, number, number, number],
  stringKey: number
): EncodedPayload {
  const rng = makeRng(seed);
  const mixer = new ArxMixer(stringKey);
  const hash  = fnv1a(plain);

  const encrypted = plain.map(b => {
    const k = (rng() ^ mixer.nextByte()) & 0xFF;
    return b ^ k;
  });

  return { bytes: encrypted, hash };
}

// ── Base-85 armour (Ascii85 variant) ────────────────────────
const B85_CHARS =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

export function encodeBase85(bytes: number[]): string {
  const out: string[] = [];
  const pad = (4 - (bytes.length % 4)) % 4;
  const padded = [...bytes, ...new Array(pad).fill(0)];

  for (let i = 0; i < padded.length; i += 4) {
    let val = ((padded[i] << 24) | (padded[i+1] << 16) |
               (padded[i+2] << 8) | padded[i+3]) >>> 0;
    const chunk: string[] = [];
    for (let j = 0; j < 5; j++) {
      chunk.unshift(B85_CHARS[val % 85]);
      val = Math.floor(val / 85);
    }
    out.push(...chunk);
  }

  // Strip padding chars from end
  return out.slice(0, out.length - pad).join("");
}

export function decodeBase85(str: string): number[] {
  const charMap: Record<string, number> = {};
  for (let i = 0; i < B85_CHARS.length; i++) charMap[B85_CHARS[i]] = i;

  const pad = (5 - (str.length % 5)) % 5;
  const padded = str + B85_CHARS[84].repeat(pad);
  const out: number[] = [];

  for (let i = 0; i < padded.length; i += 5) {
    let val = 0;
    for (let j = 0; j < 5; j++) {
      val = val * 85 + charMap[padded[i + j]];
    }
    out.push((val >>> 24) & 0xFF);
    out.push((val >>> 16) & 0xFF);
    out.push((val >>>  8) & 0xFF);
    out.push( val         & 0xFF);
  }

  return out.slice(0, out.length - pad);
}

// ── Chunked payload packaging ─────────────────────────────────
// Split payload into fixed-size chunks with per-chunk headers.
// Chunk reordering is applied: chunks are emitted in a shuffled
// order and the VM reassembles them via stored sequence indices.
export interface Chunk {
  seq:   number;   // original position
  bytes: number[];
}

export function chunkPayload(bytes: number[], chunkSize = 64): Chunk[] {
  const chunks: Chunk[] = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    chunks.push({ seq: chunks.length, bytes: bytes.slice(i, i + chunkSize) });
  }
  return chunks;
}

/** Fisher-Yates shuffle (seeded) and return [shuffled, seqOrder] */
export function shuffleChunks(
  chunks: Chunk[],
  seed32: number
): { shuffled: Chunk[]; order: number[] } {
  let s = u32(seed32);
  const lcg = () => { s = u32(Math.imul(s, 1664525) + 1013904223); return s; };

  const arr = [...chunks];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = lcg() % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }

  return { shuffled: arr, order: arr.map(c => c.seq) };
}

// ── Paired-Key String Transformation ─────────────────────────
// Encrypt a constant string with a per-string XOR pair (k1, k2).
// k1 XORs even bytes, k2 XORs odd bytes.
// Keys are derived from the ARX mixer seeded with the string index.
export function encryptString(
  s: string,
  mixerSeed: number,
  strIndex: number
): { encrypted: number[]; k1: number; k2: number } {
  const m = new ArxMixer(mixerSeed ^ (strIndex * 0x9E3779B9));
  const k1 = m.nextByte();
  const k2 = m.nextByte();
  const enc = new TextEncoder().encode(s);
  const encrypted = Array.from(enc).map((b, i) => b ^ (i % 2 === 0 ? k1 : k2));
  return { encrypted, k1, k2 };
}
