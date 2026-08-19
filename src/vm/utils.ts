export function mulberry32(seed: number) {
  let s = (seed >>> 0)
  return () => {
    s += 0x6D2B79F5
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export function randomName(rng: () => number, len = 6): string {
  const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  const alnum = alpha + "0123456789"
  let name = alpha[Math.floor(rng() * alpha.length)]
  for (let i = 1; i < len; i++) name += alnum[Math.floor(rng() * alnum.length)]
  return name
}

export function randomNames(rng: () => number, count: number, len = 6): string[] {
  const used = new Set<string>()
  const result: string[] = []
  while (result.length < count) {
    const n = randomName(rng, len)
    if (!used.has(n)) { used.add(n); result.push(n) }
  }
  return result
}

// ARX-style 32-bit mixer
export function arxMix(x: number, seed: number): number {
  x = (x ^ (x >>> 16)) >>> 0
  x = Math.imul(x, 0x45d9f3b) >>> 0
  x = (x ^ (x >>> 16)) >>> 0
  x = Math.imul(x, seed | 1) >>> 0
  x = (x ^ (x >>> 16)) >>> 0
  return x >>> 0
}

// FNV-style hash
export function fnvHash(data: number[], seed: number): number {
  let h = seed >>> 0
  for (const b of data) {
    h = Math.imul(h, 0x01000193) >>> 0
    h = (h ^ b) >>> 0
  }
  return h
}

// Seeded PRNG key schedule
export function keySchedule(seed: number, len: number): number[] {
  const rng = mulberry32(seed)
  return Array.from({ length: len }, () => Math.floor(rng() * 256))
}

// Base85 encode
const B85 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'

export function base85Encode(data: number[]): string {
  let out = ''
  for (let i = 0; i < data.length; i += 4) {
    let v = 0
    const chunk = Math.min(4, data.length - i)
    for (let j = 0; j < 4; j++) v = v * 256 + (j < chunk ? data[i + j] : 0)
    v = v >>> 0
    const chars: string[] = []
    for (let j = 0; j < 5; j++) { chars.push(B85[v % 85]); v = Math.floor(v / 85) }
    out += chars.reverse().slice(0, chunk + 1).join('')
  }
  return out
}

// Shuffle array with seeded rng
export function seededShuffle<T>(arr: T[], rng: () => number): T[] {
  const a = [...arr]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

// Opcode permutation table
export function buildOpcodePermutation(count: number, rng: () => number): number[] {
  const perm = Array.from({ length: count }, (_, i) => i)
  return seededShuffle(perm, rng)
}

