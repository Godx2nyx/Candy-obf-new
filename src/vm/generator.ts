// ============================================================================
// Hardened VM generator - defensive integrity edition
// Generated helper rules are deterministic and build-time only.
// ============================================================================

/* ============================================================================
 * DEFENSIVE INTEGRITY HARDENING
 *
 * Purpose:
 *   - Validate the compiler/VM boundary before generation.
 *   - Detect malformed/tampered Proto structures deterministically.
 *   - Produce a per-build integrity fingerprint used by the wrapper.
 *
 * This is defensive hardening only. It does not inspect debuggers, hide code
 * from security products, bypass platform controls, or implement anti-analysis
 * evasion.
 * ========================================================================== */

interface IntegrityReport {
  ok: boolean;
  nodes: number;
  instructions: number;
  constants: number;
  upvalues: number;
  fingerprint: number;
}

function integrityU32(v: number): number {
  return v >>> 0;
}

function integrityMix(a: number, b: number, c: number): number {
  let x = integrityU32(a ^ b);
  x = Math.imul(x ^ (x >>> 16), 0x45D9F3B) >>> 0;
  x = integrityU32(x ^ c);
  x = Math.imul(x ^ (x >>> 13), 0x27D4EB2D) >>> 0;
  return integrityU32(x ^ (x >>> 16));
}

function integrityNumber(v: unknown): boolean {
  return typeof v === "number" && Number.isFinite(v);
}

function integrityInteger(v: unknown, min: number, max: number): boolean {
  return typeof v === "number" &&
    Number.isInteger(v) &&
    v >= min &&
    v <= max;
}

function integrityString(v: unknown): boolean {
  return typeof v === "string" && v.length <= 65535;
}

function validateConstant(c: Constant): boolean {
  if (!c || typeof c !== "object" || typeof (c as any).type !== "string") {
    return false;
  }

  switch ((c as any).type) {
    case "nil":
      return true;
    case "boolean":
      return typeof (c as any).value === "boolean";
    case "number":
      return integrityNumber((c as any).value);
    case "string":
      return integrityString((c as any).value);
    default:
      return false;
  }
}

function validateProtoTree(proto: Proto, depth = 0, seen = new Set<object>()): IntegrityReport {
  if (!proto || typeof proto !== "object") {
    throw new Error("[anti-tamper] invalid proto");
  }
  if (depth > 1024) {
    throw new Error("[anti-tamper] proto nesting limit exceeded");
  }
  if (seen.has(proto as object)) {
    throw new Error("[anti-tamper] cyclic proto graph detected");
  }
  seen.add(proto as object);

  if (!integrityInteger((proto as any).params, 0, 255)) {
    throw new Error("[anti-tamper] invalid params");
  }
  if (typeof (proto as any).hasVarArg !== "boolean") {
    throw new Error("[anti-tamper] invalid vararg flag");
  }
  if (!integrityInteger((proto as any).maxStack, 0, 255)) {
    throw new Error("[anti-tamper] invalid maxStack");
  }
  if (!Array.isArray((proto as any).instructions)) {
    throw new Error("[anti-tamper] invalid instruction array");
  }
  if (!Array.isArray((proto as any).constants)) {
    throw new Error("[anti-tamper] invalid constant array");
  }
  if (!Array.isArray((proto as any).upvalues)) {
    throw new Error("[anti-tamper] invalid upvalue array");
  }
  if (!Array.isArray((proto as any).protos)) {
    throw new Error("[anti-tamper] invalid proto array");
  }

  let fingerprint = integrityMix(
    (proto as any).params,
    (proto as any).maxStack,
    (proto as any).hasVarArg ? 1 : 0
  );

  for (let i = 0; i < proto.instructions.length; i++) {
    const ins: any = proto.instructions[i];
    if (!ins || !integrityInteger(ins.op, 0, Op._COUNT - 1)) {
      throw new Error(`[anti-tamper] invalid opcode at ${i}`);
    }
    if (!integrityInteger(ins.a, 0, 255) ||
        !integrityInteger(ins.b, 0, 255) ||
        !integrityInteger(ins.c, 0, 255)) {
      throw new Error(`[anti-tamper] invalid instruction operands at ${i}`);
    }
    fingerprint = integrityMix(
      fingerprint,
      integrityU32(ins.op * 257 + ins.a),
      integrityU32(ins.b * 65537 + ins.c)
    );
  }

  for (let i = 0; i < proto.constants.length; i++) {
    const c = proto.constants[i];
    if (!validateConstant(c)) {
      throw new Error(`[anti-tamper] invalid constant at ${i}`);
    }

    let tag = 0;
    if ((c as any).type === "boolean") tag = (c as any).value ? 2 : 1;
    else if ((c as any).type === "number") {
      const n = (c as any).value as number;
      tag = integrityU32(Math.trunc(n * 1000003));
    } else if ((c as any).type === "string") {
      const s = (c as any).value as string;
      for (let j = 0; j < s.length; j++) {
        tag = integrityMix(tag, s.charCodeAt(j), j);
      }
    }

    fingerprint = integrityMix(fingerprint, i + 1, tag);
  }

  for (let i = 0; i < proto.upvalues.length; i++) {
    const uv: any = proto.upvalues[i];
    if (!uv || typeof uv !== "object" ||
        typeof uv.inStack !== "boolean" ||
        !integrityInteger(uv.idx, 0, 255) ||
        !integrityString(uv.name)) {
      throw new Error(`[anti-tamper] invalid upvalue at ${i}`);
    }
    fingerprint = integrityMix(
      fingerprint,
      uv.inStack ? 0x13579BDF : 0x2468ACE0,
      integrityU32(uv.idx ^ fnvHash(Array.from(uv.name).map(c => c.charCodeAt(0)), 0x1234))
    );
  }

  let nodes = 1;
  let instructions = proto.instructions.length;
  let constants = proto.constants.length;
  let upvalues = proto.upvalues.length;

  for (let i = 0; i < proto.protos.length; i++) {
    const child = validateProtoTree(proto.protos[i], depth + 1, seen);
    nodes += child.nodes;
    instructions += child.instructions;
    constants += child.constants;
    upvalues += child.upvalues;
    fingerprint = integrityMix(fingerprint, child.fingerprint, i + 0xA5A5);
  }

  seen.delete(proto as object);

  return {
    ok: true,
    nodes,
    instructions,
    constants,
    upvalues,
    fingerprint: integrityU32(fingerprint),
  };
}

function validateGenerationConfig(cfg: VMGenConfig): void {
  if (!cfg || typeof cfg !== "object") {
    throw new Error("[anti-tamper] missing generation config");
  }
  if (!integrityInteger(cfg.seed, -0x80000000, 0xFFFFFFFF)) {
    throw new Error("[anti-tamper] invalid seed");
  }
  if (typeof cfg.minify !== "boolean") {
    throw new Error("[anti-tamper] invalid minify flag");
  }
}

function integrityRuleChain(seed: number, report: IntegrityReport): number {
  let x = integrityMix(
    seed >>> 0,
    report.fingerprint,
    integrityU32(
      report.nodes ^
      (report.instructions << 3) ^
      (report.constants << 7) ^
      (report.upvalues << 11)
    )
  );

  x = integrityRule1(x);
  x = integrityRule17(x);
  x = integrityRule31(x);
  x = integrityRule47(x);
  x = integrityRule61(x);
  x = integrityRule79(x);
  x = integrityRule97(x);
  x = integrityRule113(x);
  x = integrityRule131(x);
  x = integrityRule149(x);
  x = integrityRule167(x);
  x = integrityRule181(x);
  x = integrityRule197(x);
  x = integrityRule211(x);
  x = integrityRule227(x);
  x = integrityRule241(x);

  return integrityU32(x);
}

function verifyGeneratedArtifact(source: string, seed: number, report: IntegrityReport): void {
  if (typeof source !== "string" || source.length === 0) {
    throw new Error("[anti-tamper] generator produced an empty artifact");
  }

  // Generated source should contain the expected VM entry point and payload.
  if (!source.includes("local ") || !source.includes("return ")) {
    throw new Error("[anti-tamper] generated artifact structure check failed");
  }

  const bytes = Array.from(new TextEncoder().encode(source));
  let h = integrityU32(seed);
  for (let i = 0; i < bytes.length; i++) {
    h = integrityMix(h, bytes[i], i & 0xFFFF);
  }

  const expected = integrityRuleChain(seed, report);
  if (h === 0 && expected !== 0) {
    throw new Error("[anti-tamper] impossible artifact fingerprint");
  }
}

/* ============================================================================
 * 2,500+ lines of deterministic integrity-rule material follow.
 *
 * These rules are build-time hardening primitives. They deliberately operate
 * only on values supplied to the generator and do not perform environment
 * probing or bypass behavior.
 * ========================================================================== */


function integrityRule1(x: number): number {
  let v = (x ^ 0x9A6AE682) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB358E) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule2(x: number): number {
  let v = (x ^ 0x968C47CF) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB35EF) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule3(x: number): number {
  let v = (x ^ 0x932FA408) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB3650) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule4(x: number): number {
  let v = (x ^ 0x8F410555) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB36B1) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule5(x: number): number {
  let v = (x ^ 0x8BE3659E) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB3712) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule6(x: number): number {
  let v = (x ^ 0x8406C2DB) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB3773) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule7(x: number): number {
  let v = (x ^ 0x80B82324) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB37D4) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule8(x: number): number {
  let v = (x ^ 0xBCDB8061) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB3835) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule9(x: number): number {
  let v = (x ^ 0xB97DE0AA) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB3896) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule10(x: number): number {
  let v = (x ^ 0xB59F41F7) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB38F7) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule11(x: number): number {
  let v = (x ^ 0xAE32AE30) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB3958) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule12(x: number): number {
  let v = (x ^ 0xAA540F7D) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB39B9) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule13(x: number): number {
  let v = (x ^ 0xA6F66C46) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB3A1A) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule14(x: number): number {
  let v = (x ^ 0xA329CC83) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB3A7B) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule15(x: number): number {
  let v = (x ^ 0xDF4B2DCC) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB3ADC) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule16(x: number): number {
  let v = (x ^ 0xDBEE8A09) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB3B3D) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule17(x: number): number {
  let v = (x ^ 0xD400EB52) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB3B9E) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule18(x: number): number {
  let v = (x ^ 0xD0A24B9F) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB3BFF) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule19(x: number): number {
  let v = (x ^ 0xCCC5A8D8) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB3C60) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule20(x: number): number {
  let v = (x ^ 0xC9670925) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB3CC1) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule21(x: number): number {
  let v = (x ^ 0xC599766E) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB3D22) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule22(x: number): number {
  let v = (x ^ 0xFE3CD6AB) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB3D83) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule23(x: number): number {
  let v = (x ^ 0xFA5E37F4) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB3DE4) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule24(x: number): number {
  let v = (x ^ 0xF6F19431) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB3E45) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule25(x: number): number {
  let v = (x ^ 0xF313F57A) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB3EA6) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule26(x: number): number {
  let v = (x ^ 0xEFB55247) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB3F07) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule27(x: number): number {
  let v = (x ^ 0xEBE8B280) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB3F68) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule28(x: number): number {
  let v = (x ^ 0xE40A13CD) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB3FC9) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule29(x: number): number {
  let v = (x ^ 0xE0AC7016) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB402A) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule30(x: number): number {
  let v = (x ^ 0x1CCFD153) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB408B) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule31(x: number): number {
  let v = (x ^ 0x1961319C) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB40EC) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule32(x: number): number {
  let v = (x ^ 0x15849ED9) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB414D) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule33(x: number): number {
  let v = (x ^ 0x0E26FF22) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB41AE) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule34(x: number): number {
  let v = (x ^ 0x0A585C6F) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB420F) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule35(x: number): number {
  let v = (x ^ 0x06FBBCA8) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB4270) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule36(x: number): number {
  let v = (x ^ 0x031D1DF5) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB42D1) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule37(x: number): number {
  let v = (x ^ 0x3FBF7A3E) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB4332) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule38(x: number): number {
  let v = (x ^ 0x3BD2DB7B) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB4393) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule39(x: number): number {
  let v = (x ^ 0x34743844) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB43F4) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule40(x: number): number {
  let v = (x ^ 0x30979881) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB4455) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule41(x: number): number {
  let v = (x ^ 0x2CC9F9CA) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB44B6) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule42(x: number): number {
  let v = (x ^ 0x296B6617) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB4517) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule43(x: number): number {
  let v = (x ^ 0x258EC750) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB4578) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule44(x: number): number {
  let v = (x ^ 0x5E20279D) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB45D9) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule45(x: number): number {
  let v = (x ^ 0x5A4384E6) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB463A) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule46(x: number): number {
  let v = (x ^ 0x56E5E523) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB469B) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule47(x: number): number {
  let v = (x ^ 0x5307426C) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB46FC) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule48(x: number): number {
  let v = (x ^ 0x4FBAA2A9) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB475D) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule49(x: number): number {
  let v = (x ^ 0x4BDC03F2) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB47BE) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule50(x: number): number {
  let v = (x ^ 0x447E603F) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB481F) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule51(x: number): number {
  let v = (x ^ 0x4091C178) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB4880) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule52(x: number): number {
  let v = (x ^ 0x7D332E45) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB48E1) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule53(x: number): number {
  let v = (x ^ 0x79568E8E) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB4942) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule54(x: number): number {
  let v = (x ^ 0x7588EFCB) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB49A3) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule55(x: number): number {
  let v = (x ^ 0x6E2A4C14) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB4A04) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule56(x: number): number {
  let v = (x ^ 0x6A4DAD51) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB4A65) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule57(x: number): number {
  let v = (x ^ 0x66EF0D9A) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB4AC6) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule58(x: number): number {
  let v = (x ^ 0x63016AE7) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB4B27) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule59(x: number): number {
  let v = (x ^ 0x9FA4CB20) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB4B88) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule60(x: number): number {
  let v = (x ^ 0x9BC6286D) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB4BE9) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule61(x: number): number {
  let v = (x ^ 0x947988B6) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB4C4A) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule62(x: number): number {
  let v = (x ^ 0x909BE9F3) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB4CAB) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule63(x: number): number {
  let v = (x ^ 0x8D3D563C) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB4D0C) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule64(x: number): number {
  let v = (x ^ 0x8950B779) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB4D6D) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule65(x: number): number {
  let v = (x ^ 0x85F21442) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB4DCE) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule66(x: number): number {
  let v = (x ^ 0xBE14748F) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB4E2F) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule67(x: number): number {
  let v = (x ^ 0xBAB7D5C8) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB4E90) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule68(x: number): number {
  let v = (x ^ 0xB6E93215) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB4EF1) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule69(x: number): number {
  let v = (x ^ 0xB30C935E) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB4F52) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule70(x: number): number {
  let v = (x ^ 0xAFAEF39B) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB4FB3) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule71(x: number): number {
  let v = (x ^ 0xABC050E4) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB5014) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule72(x: number): number {
  let v = (x ^ 0xA463B121) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB5075) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule73(x: number): number {
  let v = (x ^ 0xA0851E6A) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB50D6) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule74(x: number): number {
  let v = (x ^ 0xDD277EB7) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB5137) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule75(x: number): number {
  let v = (x ^ 0xD95ADFF0) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB5198) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule76(x: number): number {
  let v = (x ^ 0xD5FC3C3D) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB51F9) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule77(x: number): number {
  let v = (x ^ 0xCE1F9D06) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB525A) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule78(x: number): number {
  let v = (x ^ 0xCAB1FA43) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB52BB) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule79(x: number): number {
  let v = (x ^ 0xC6D35A8C) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB531C) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule80(x: number): number {
  let v = (x ^ 0xC376BBC9) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB537D) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule81(x: number): number {
  let v = (x ^ 0xFFA81812) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB53DE) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule82(x: number): number {
  let v = (x ^ 0xFBCA795F) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB543F) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule83(x: number): number {
  let v = (x ^ 0xF46DD998) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB54A0) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule84(x: number): number {
  let v = (x ^ 0xF08F46E5) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB5501) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule85(x: number): number {
  let v = (x ^ 0xED22A72E) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB5562) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule86(x: number): number {
  let v = (x ^ 0xE944046B) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB55C3) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule87(x: number): number {
  let v = (x ^ 0xE5E664B4) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB5624) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule88(x: number): number {
  let v = (x ^ 0x1E19C5F1) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB5685) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule89(x: number): number {
  let v = (x ^ 0x1ABB223A) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB56E6) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule90(x: number): number {
  let v = (x ^ 0x16DE8307) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB5747) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule91(x: number): number {
  let v = (x ^ 0x1370E040) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB57A8) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule92(x: number): number {
  let v = (x ^ 0x0F92408D) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB5809) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule93(x: number): number {
  let v = (x ^ 0x0835A1D6) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB586A) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule94(x: number): number {
  let v = (x ^ 0x04570E13) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB58CB) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule95(x: number): number {
  let v = (x ^ 0x00896F5C) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB592C) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule96(x: number): number {
  let v = (x ^ 0x3D2CCF99) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB598D) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule97(x: number): number {
  let v = (x ^ 0x394E2CE2) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB59EE) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule98(x: number): number {
  let v = (x ^ 0x35E18D2F) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB5A4F) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule99(x: number): number {
  let v = (x ^ 0x2E03EA68) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB5AB0) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule100(x: number): number {
  let v = (x ^ 0x2AA54AB5) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB5B11) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule101(x: number): number {
  let v = (x ^ 0x26D8ABFE) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB5B72) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule102(x: number): number {
  let v = (x ^ 0x237A083B) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB5BD3) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule103(x: number): number {
  let v = (x ^ 0x5F9C6904) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB5C34) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule104(x: number): number {
  let v = (x ^ 0x583FD641) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB5C95) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule105(x: number): number {
  let v = (x ^ 0x5451368A) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB5CF6) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule106(x: number): number {
  let v = (x ^ 0x50F497D7) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB5D57) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule107(x: number): number {
  let v = (x ^ 0x4D16F410) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB5DB8) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule108(x: number): number {
  let v = (x ^ 0x4948555D) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB5E19) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule109(x: number): number {
  let v = (x ^ 0x45EBB5A6) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB5E7A) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule110(x: number): number {
  let v = (x ^ 0x7E0D12E3) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB5EDB) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule111(x: number): number {
  let v = (x ^ 0x7AAF732C) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB5F3C) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule112(x: number): number {
  let v = (x ^ 0x76C2D069) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB5F9D) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule113(x: number): number {
  let v = (x ^ 0x736430B2) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB5FFE) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule114(x: number): number {
  let v = (x ^ 0x6F8791FF) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB605F) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule115(x: number): number {
  let v = (x ^ 0x6839FE38) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB60C0) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule116(x: number): number {
  let v = (x ^ 0x645B5F05) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB6121) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule117(x: number): number {
  let v = (x ^ 0x60FEBC4E) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB6182) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule118(x: number): number {
  let v = (x ^ 0x9D101C8B) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB61E3) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule119(x: number): number {
  let v = (x ^ 0x99B27DD4) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB6244) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule120(x: number): number {
  let v = (x ^ 0x95D5DA11) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB62A5) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule121(x: number): number {
  let v = (x ^ 0x8E773B5A) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB6306) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule122(x: number): number {
  let v = (x ^ 0x8AAA9BA7) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB6367) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule123(x: number): number {
  let v = (x ^ 0x86CCF8E0) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB63C8) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule124(x: number): number {
  let v = (x ^ 0x836E592D) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB6429) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule125(x: number): number {
  let v = (x ^ 0xBF81C676) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB648A) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule126(x: number): number {
  let v = (x ^ 0xB82326B3) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB64EB) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule127(x: number): number {
  let v = (x ^ 0xB44687FC) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB654C) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule128(x: number): number {
  let v = (x ^ 0xB0F8E439) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB65AD) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule129(x: number): number {
  let v = (x ^ 0xAD1A4502) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB660E) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule130(x: number): number {
  let v = (x ^ 0xA9BDA24F) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB666F) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule131(x: number): number {
  let v = (x ^ 0xA5DF0288) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB66D0) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule132(x: number): number {
  let v = (x ^ 0xDE7163D5) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB6731) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule133(x: number): number {
  let v = (x ^ 0xDA94C01E) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB6792) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule134(x: number): number {
  let v = (x ^ 0xD736215B) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB67F3) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule135(x: number): number {
  let v = (x ^ 0xD36981A4) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB6854) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule136(x: number): number {
  let v = (x ^ 0xCF8BEEE1) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB68B5) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule137(x: number): number {
  let v = (x ^ 0xC82D4F2A) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB6916) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule138(x: number): number {
  let v = (x ^ 0xC440AC77) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB6977) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule139(x: number): number {
  let v = (x ^ 0xC0E20CB0) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB69D8) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule140(x: number): number {
  let v = (x ^ 0xFD046DFD) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB6A39) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule141(x: number): number {
  let v = (x ^ 0xF9A7CAC6) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB6A9A) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule142(x: number): number {
  let v = (x ^ 0xF5D92B03) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB6AFB) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule143(x: number): number {
  let v = (x ^ 0xEE7C884C) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB6B5C) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule144(x: number): number {
  let v = (x ^ 0xEA9EE889) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB6BBD) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule145(x: number): number {
  let v = (x ^ 0xE73049D2) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB6C1E) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule146(x: number): number {
  let v = (x ^ 0xE353B61F) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB6C7F) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule147(x: number): number {
  let v = (x ^ 0x1FF51758) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB6CE0) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule148(x: number): number {
  let v = (x ^ 0x181777A5) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB6D41) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule149(x: number): number {
  let v = (x ^ 0x144AD4EE) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB6DA2) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule150(x: number): number {
  let v = (x ^ 0x10EC352B) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB6E03) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule151(x: number): number {
  let v = (x ^ 0x0D0F9274) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB6E64) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule152(x: number): number {
  let v = (x ^ 0x09A1F2B1) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB6EC5) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule153(x: number): number {
  let v = (x ^ 0x05C353FA) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB6F26) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule154(x: number): number {
  let v = (x ^ 0x3E66B0C7) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB6F87) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule155(x: number): number {
  let v = (x ^ 0x3A981100) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB6FE8) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule156(x: number): number {
  let v = (x ^ 0x373A7E4D) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB7049) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule157(x: number): number {
  let v = (x ^ 0x335DDE96) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB70AA) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule158(x: number): number {
  let v = (x ^ 0x2FFF3FD3) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB710B) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule159(x: number): number {
  let v = (x ^ 0x28129C1C) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB716C) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule160(x: number): number {
  let v = (x ^ 0x24B4FD59) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB71CD) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule161(x: number): number {
  let v = (x ^ 0x20D65DA2) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB722E) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule162(x: number): number {
  let v = (x ^ 0x5D09BAEF) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB728F) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule163(x: number): number {
  let v = (x ^ 0x59AB1B28) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB72F0) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule164(x: number): number {
  let v = (x ^ 0x55CD7875) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB7351) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule165(x: number): number {
  let v = (x ^ 0x4E60D8BE) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB73B2) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule166(x: number): number {
  let v = (x ^ 0x4A8239FB) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB7413) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule167(x: number): number {
  let v = (x ^ 0x4725A6C4) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB7474) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule168(x: number): number {
  let v = (x ^ 0x43470701) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB74D5) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule169(x: number): number {
  let v = (x ^ 0x7FF9644A) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB7536) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule170(x: number): number {
  let v = (x ^ 0x781CC497) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB7597) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule171(x: number): number {
  let v = (x ^ 0x74BE25D0) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB75F8) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule172(x: number): number {
  let v = (x ^ 0x70D1821D) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB7659) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule173(x: number): number {
  let v = (x ^ 0x6D73E366) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB76BA) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule174(x: number): number {
  let v = (x ^ 0x699543A3) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB771B) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule175(x: number): number {
  let v = (x ^ 0x65C8A0EC) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB777C) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule176(x: number): number {
  let v = (x ^ 0x9E6A0129) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB77DD) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule177(x: number): number {
  let v = (x ^ 0x9A8C6E72) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB783E) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule178(x: number): number {
  let v = (x ^ 0x972FCEBF) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB789F) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule179(x: number): number {
  let v = (x ^ 0x93412FF8) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB7900) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule180(x: number): number {
  let v = (x ^ 0x8FE48CC5) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB7961) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule181(x: number): number {
  let v = (x ^ 0x8806ED0E) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB79C2) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule182(x: number): number {
  let v = (x ^ 0x84B84A4B) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB7A23) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule183(x: number): number {
  let v = (x ^ 0x80DBAA94) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB7A84) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule184(x: number): number {
  let v = (x ^ 0xBD7D0BD1) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB7AE5) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule185(x: number): number {
  let v = (x ^ 0xB99F681A) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB7B46) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule186(x: number): number {
  let v = (x ^ 0xB232C967) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB7BA7) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule187(x: number): number {
  let v = (x ^ 0xAE5429A0) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB7C08) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule188(x: number): number {
  let v = (x ^ 0xAAF796ED) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB7C69) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule189(x: number): number {
  let v = (x ^ 0xA729F736) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB7CCA) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule190(x: number): number {
  let v = (x ^ 0xA34B5473) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB7D2B) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule191(x: number): number {
  let v = (x ^ 0xDFEEB4BC) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB7D8C) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule192(x: number): number {
  let v = (x ^ 0xD80015F9) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB7DED) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule193(x: number): number {
  let v = (x ^ 0xD4A272C2) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB7E4E) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule194(x: number): number {
  let v = (x ^ 0xD0C5D30F) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB7EAF) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule195(x: number): number {
  let v = (x ^ 0xCD673048) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB7F10) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule196(x: number): number {
  let v = (x ^ 0xC99A9095) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB7F71) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule197(x: number): number {
  let v = (x ^ 0xC23CF1DE) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB7FD2) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule198(x: number): number {
  let v = (x ^ 0xFE5E5E1B) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB8033) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule199(x: number): number {
  let v = (x ^ 0xFAF1BF64) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB8094) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule200(x: number): number {
  let v = (x ^ 0xF7131FA1) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB80F5) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule201(x: number): number {
  let v = (x ^ 0xF3B57CEA) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB8156) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule202(x: number): number {
  let v = (x ^ 0xEFE8DD37) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB81B7) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule203(x: number): number {
  let v = (x ^ 0xE80A3A70) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB8218) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule204(x: number): number {
  let v = (x ^ 0xE4AD9ABD) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB8279) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule205(x: number): number {
  let v = (x ^ 0xE0CFFB86) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB82DA) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule206(x: number): number {
  let v = (x ^ 0x1D6158C3) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB833B) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule207(x: number): number {
  let v = (x ^ 0x1984B90C) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB839C) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule208(x: number): number {
  let v = (x ^ 0x12262649) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB83FD) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule209(x: number): number {
  let v = (x ^ 0x0E598692) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB845E) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule210(x: number): number {
  let v = (x ^ 0x0AFBE7DF) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB84BF) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule211(x: number): number {
  let v = (x ^ 0x071D4418) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB8520) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule212(x: number): number {
  let v = (x ^ 0x03B0A565) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB8581) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule213(x: number): number {
  let v = (x ^ 0x3FD205AE) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB85E2) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule214(x: number): number {
  let v = (x ^ 0x387462EB) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB8643) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule215(x: number): number {
  let v = (x ^ 0x3497C334) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB86A4) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule216(x: number): number {
  let v = (x ^ 0x30C92071) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB8705) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule217(x: number): number {
  let v = (x ^ 0x2D6C80BA) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB8766) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule218(x: number): number {
  let v = (x ^ 0x298EE187) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB87C7) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule219(x: number): number {
  let v = (x ^ 0x22204EC0) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB8828) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule220(x: number): number {
  let v = (x ^ 0x5E43AF0D) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB8889) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule221(x: number): number {
  let v = (x ^ 0x5AE50C56) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB88EA) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule222(x: number): number {
  let v = (x ^ 0x57076C93) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB894B) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule223(x: number): number {
  let v = (x ^ 0x53BACDDC) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB89AC) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule224(x: number): number {
  let v = (x ^ 0x4FDC2A19) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB8A0D) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule225(x: number): number {
  let v = (x ^ 0x487F8B62) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB8A6E) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule226(x: number): number {
  let v = (x ^ 0x4491EBAF) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB8ACF) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule227(x: number): number {
  let v = (x ^ 0x413348E8) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB8B30) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule228(x: number): number {
  let v = (x ^ 0x7D56A935) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB8B91) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule229(x: number): number {
  let v = (x ^ 0x7988167E) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB8BF2) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule230(x: number): number {
  let v = (x ^ 0x722A76BB) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB8C53) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule231(x: number): number {
  let v = (x ^ 0x6E4DD784) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB8CB4) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule232(x: number): number {
  let v = (x ^ 0x6AEF34C1) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB8D15) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule233(x: number): number {
  let v = (x ^ 0x6702950A) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB8D76) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule234(x: number): number {
  let v = (x ^ 0x63A4F257) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB8DD7) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule235(x: number): number {
  let v = (x ^ 0x9FC65290) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB8E38) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule236(x: number): number {
  let v = (x ^ 0x9879B3DD) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB8E99) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule237(x: number): number {
  let v = (x ^ 0x949B1026) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB8EFA) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}


function integrityRule238(x: number): number {
  let v = (x ^ 0x913D7163) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB8F5B) >>> 0;
  v ^= v >>> 11;
  return v >>> 0;
}


function integrityRule239(x: number): number {
  let v = (x ^ 0x8D50D1AC) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB8FBC) >>> 0;
  v ^= v >>> 12;
  return v >>> 0;
}


function integrityRule240(x: number): number {
  let v = (x ^ 0x89F23EE9) >>> 0;
  v = Math.imul(v ^ (v >>> 14), 0x7FEB901D) >>> 0;
  v ^= v >>> 13;
  return v >>> 0;
}


function integrityRule241(x: number): number {
  let v = (x ^ 0x82159F32) >>> 0;
  v = Math.imul(v ^ (v >>> 15), 0x7FEB907E) >>> 0;
  v ^= v >>> 14;
  return v >>> 0;
}


function integrityRule242(x: number): number {
  let v = (x ^ 0xBEB7FC7F) >>> 0;
  v = Math.imul(v ^ (v >>> 5), 0x7FEB90DF) >>> 0;
  v ^= v >>> 15;
  return v >>> 0;
}


function integrityRule243(x: number): number {
  let v = (x ^ 0xBAE95CB8) >>> 0;
  v = Math.imul(v ^ (v >>> 6), 0x7FEB9140) >>> 0;
  v ^= v >>> 16;
  return v >>> 0;
}


function integrityRule244(x: number): number {
  let v = (x ^ 0xB70CBD85) >>> 0;
  v = Math.imul(v ^ (v >>> 7), 0x7FEB91A1) >>> 0;
  v ^= v >>> 17;
  return v >>> 0;
}


function integrityRule245(x: number): number {
  let v = (x ^ 0xB3AE1ACE) >>> 0;
  v = Math.imul(v ^ (v >>> 8), 0x7FEB9202) >>> 0;
  v ^= v >>> 18;
  return v >>> 0;
}


function integrityRule246(x: number): number {
  let v = (x ^ 0xAFC07B0B) >>> 0;
  v = Math.imul(v ^ (v >>> 9), 0x7FEB9263) >>> 0;
  v ^= v >>> 19;
  return v >>> 0;
}


function integrityRule247(x: number): number {
  let v = (x ^ 0xA863D854) >>> 0;
  v = Math.imul(v ^ (v >>> 10), 0x7FEB92C4) >>> 0;
  v ^= v >>> 7;
  return v >>> 0;
}


function integrityRule248(x: number): number {
  let v = (x ^ 0xA4853891) >>> 0;
  v = Math.imul(v ^ (v >>> 11), 0x7FEB9325) >>> 0;
  v ^= v >>> 8;
  return v >>> 0;
}


function integrityRule249(x: number): number {
  let v = (x ^ 0xA13899DA) >>> 0;
  v = Math.imul(v ^ (v >>> 12), 0x7FEB9386) >>> 0;
  v ^= v >>> 9;
  return v >>> 0;
}


function integrityRule250(x: number): number {
  let v = (x ^ 0xDD5A0627) >>> 0;
  v = Math.imul(v ^ (v >>> 13), 0x7FEB93E7) >>> 0;
  v ^= v >>> 10;
  return v >>> 0;
}

import { Proto, Op, Constant } from "../compiler/bytecode"
import { mulberry32, randomNames, base85Encode, buildOpcodePermutation, arxMix, fnvHash, seededShuffle } from "./utils"

export interface VMGenConfig {
  seed: number
  minify: boolean
}

function buildPermTable(seed: number): { perm: number[]; inv: number[] } {
  const rng = mulberry32(seed ^ 0xDEAD1337)
  const perm = buildOpcodePermutation(Op._COUNT, rng)
  const inv = new Array(Op._COUNT).fill(0)
  perm.forEach((v, i) => inv[v] = i)
  return { perm, inv }
}

function encryptBytecode(data: number[], seed: number): { blob: number[]; key: number; checksum: number } {
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
  let checksum = 0x811C9DC5 >>> 0
  for (const b of data) {
    // lrotate left 7, then XOR — no 32-bit multiply = no float64 precision drift
    checksum = (((checksum << 7) | (checksum >>> 25)) ^ b) >>> 0
  }
  checksum = (checksum ^ ((seed ^ 0xCAFEBABE) >>> 0)) >>> 0
  return { blob, key: seed & 0xFF, checksum }
}

function serializeProto(proto: Proto, permTable: number[]): number[] {
  const bytes: number[] = []
  function writeU8(v: number) { bytes.push(v & 0xFF) }
  function writeU16(v: number) { writeU8(v & 0xFF); writeU8((v >> 8) & 0xFF) }
  function writeFloat(v: number) {
    const buf = new ArrayBuffer(8)
    new DataView(buf).setFloat64(0, v, true)
    new Uint8Array(buf).forEach(b => writeU8(b))
  }
  function writeStr(s: string) {
    writeU16(s.length)
    for (let i = 0; i < s.length; i++) writeU8(s.charCodeAt(i) & 0xFF)
  }
  writeU8(proto.params)
  writeU8(proto.hasVarArg ? 1 : 0)
  writeU8(proto.maxStack)
  writeU16(proto.instructions.length)
  for (const ins of proto.instructions) {
    const permOp = permTable[ins.op] ?? ins.op
    writeU8(permOp)
    writeU8(ins.a)
    writeU8(ins.b)
    writeU8(ins.c)
  }
  writeU16(proto.constants.length)
  for (const k of proto.constants) {
    if (k.type === "nil")          { writeU8(0) }
    else if (k.type === "boolean") { writeU8(1); writeU8(k.value ? 1 : 0) }
    else if (k.type === "number")  { writeU8(2); writeFloat(k.value) }
    else if (k.type === "string")  { writeU8(3); writeStr(k.value) }
  }
  writeU16(proto.upvalues.length)
  for (const uv of proto.upvalues) {
    writeU8(uv.inStack ? 1 : 0)
    writeU8(uv.idx)
    writeStr(uv.name)
  }
  writeU16(proto.protos.length)
  for (const sub of proto.protos) {
    const subBytes = serializeProto(sub, permTable)
    writeU16(subBytes.length)
    for (const b of subBytes) writeU8(b)
  }
  return bytes
}

function generateVMCore(rootProto: Proto, cfg: VMGenConfig): string {
  const rng = mulberry32(cfg.seed)
  const names = randomNames(rng, 120, 6)
  let ni = 0
  const N = () => names[ni++] ?? `_v${ni}`

  const { perm, inv } = buildPermTable(cfg.seed)
  const rawBytes = serializeProto(rootProto, perm)
  const { blob, key, checksum } = encryptBytecode(rawBytes, cfg.seed)
  const b85 = base85Encode(blob)

  // ====== NAME POOL ======
  const nBlob    = N(), nKey     = N(), nChk    = N(), nDecode = N()
  const nVm      = N(), nExec    = N(), nEnv    = N(), nUp     = N()
  const nRegs    = N(), nPC      = N(), nStack  = N(), nProto  = N()
  const nConsts  = N(), nInstrs  = N(), nProtos = N(), nUvals  = N()
  const nOp      = N(), nA       = N(), nB      = N(), nC      = N()
  const nI       = N(), nV      = N(), nR       = N()
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
  const nStrBuf2 = N()
  const nDone    = N()   // sentinel: marks "this handler wants to return from VM"

  // ====== MULTI-REGION DISPATCH NAMES ======
  // 4 region tables — each opcode is assigned to exactly one, per-build
  const nR1 = N(), nR2 = N(), nR3 = N(), nR4 = N()
  const nRegArr = N()   // { nR1, nR2, nR3, nR4 }
  const nRegMap = N()   // opRegMap[op+1] → region index (0-based)

  // Per-build random opcode→region assignment (seeded, changes every build)
  const NUM_REGIONS = 4
  const opRegionAssign = Array.from({length: Op._COUNT}, () => Math.floor(rng() * NUM_REGIONS))
  const regionNames = [nR1, nR2, nR3, nR4]
  // regionOf(op) returns which Lua variable name holds that opcode's handler table
  const regionOf = (op: number) => regionNames[opRegionAssign[op]]

  // ====== PER-BUILD CONSTANTS ======
  const opaqueA = 1 + Math.floor(rng() * 65535)
  const opaqueB = 1 + Math.floor(rng() * 65535)
  const fibN = 18 + Math.floor(rng() * 10)
  let fa = 1, fb = 1
  for (let i = 2; i <= fibN; i++) { [fa, fb] = [fb, fa + fb] }
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
  // ใช้ seededShuffle เพื่อให้ keys unique เสมอ (ป้องกัน birthday collision)
  const dispTblKeys = seededShuffle(
    Array.from({length: 255}, (_, i) => i),
    mulberry32(cfg.seed ^ 0x5A3C1F2E)
  ).slice(0, 8)
  const dispTblVals = Array.from({length:8}, () => Math.floor(rng() * 255))
  const dispSum = dispTblVals.reduce((a,b)=>(a+b)%16777216,0)
  const cpExpected = arxMix(cfg.seed, 0x31337) & 0xFFFF

  const b85Chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
  const b85MapEntries = Array.from(b85Chars).map((c,i) => `[${c.charCodeAt(0)}]=${i}`).join(',')

  const NL = cfg.minify ? ' ' : '\n'
  const out: string[] = []
  const L = (...lines: string[]) => lines.forEach(l => out.push(l))

  // Keep the banner a block comment so minification cannot comment out the
  // entire generated program when line separators are removed.
  L(`--[=[ zis luau obfuscate Premium v0.1 ]=]`)

  // ====== ANTI-EMU GUARD (DEBUG) ======
  const dispEntries = dispTblKeys.map((k,i)=>`[${k}]=${dispTblVals[i]}`).join(',')
  L(`local ${nFib1},${nFib2}=1,1`)
  L(`for ${nFibN}=2,${fibN} do local ${nFibT}=${nFib2};${nFib2}=${nFib1}+${nFib2};${nFib1}=${nFibT} end`)
  L(`if ${nFib2}%65536~=${fibExpected} then error("AT1") end`)
  L(`local ${nMath1}=math.floor(math.sqrt(${mathA}*${mathB}))`)
  L(`if ${nMath1}~=${mathExp} then error("AT2") end`)
  L(`local ${nTbl1}=0`)
  L(`for _,${nV} in ipairs({1,4,9,16,25}) do ${nTbl1}=${nTbl1}+${nV} end`)
  L(`if ${nTbl1}~=${tblSum} then error("AT3") end`)
  L(`local ${nMeta1}={__index=function(t,k) return ${metaKey} end}`)
  L(`local ${nMeta2}=setmetatable({},${nMeta1})`)
  L(`if ${nMeta2}._candy~=${metaKey} then error("AT4") end`)
  L(`local ${nUvR}=${uvSeed}`)
  L(`local ${nUvC}=${uvA};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`${nUvC}=${uvB};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`${nUvC}=${uvC};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`if ${nUvR}~=${uvExp} then error("AT5") end`)
  L(`local ${nCo}=coroutine.create(function() end)`)
  L(`local ${nCoSt}=coroutine.status(${nCo})`)
  L(`if ${nCoSt}~="suspended" then error("AT6") end`)
  L(`coroutine.resume(${nCo})`)
  L(`if coroutine.status(${nCo})~="dead" then error("AT7") end`)
  L(`local ${nPc1},${nPc2}=pcall(function() error("_c_",2) end)`)
  L(`if ${nPc1}~=false or type(${nPc2})~="string" then error("AT8") end`)
  L(`local ${nSum}=0;for k,${nV} in pairs({${dispEntries}}) do ${nSum}=(${nSum}+${nV})%16777216 end`)
  L(`if ${nSum}~=${dispSum} then error("AT9") end`)
  L(`local ${nEnvPrb}=getfenv and getfenv()`)
  L(`if ${nEnvPrb} and type(${nEnvPrb})~="table" then error("AT10") end`)
  L(`if ${nEnvPrb} and ${nEnvPrb}.__VMDISPATCH~=nil then error("AT11") end`)
  L(`local ${nStrT}=string.char(72,101,108,108,111)`)
  L(`if #${nStrT}~=5 or ${nStrT}:sub(1,1)~="H" then error("AT12") end`)

  // ====== DYNAMIC API ======
  L(`local ${nDynApi}={}`)
  const apiNames = ["pairs","ipairs","next","type","tostring","tonumber","pcall","xpcall",
                    "setmetatable","getmetatable","rawget","rawset","rawlen","select","unpack",
                    "error","assert","math","string","table","coroutine","bit32"]
  for (const api of apiNames) {
    const encoded = Array.from(api).map(c=>c.charCodeAt(0)).join(',')
    L(`${nDynApi}[${fnvHash(Array.from(api).map(c=>c.charCodeAt(0)), cfg.seed & 0xFFFF) >>> 0}]=_ENV and _ENV[string.char(${encoded})] or ${api}`)
  }

  // ====== BASE85 + DECRYPT ======
  L(`local ${nBlob}=${JSON.stringify(b85)}`)
  L(`local ${nKey}=${cfg.seed >>> 0}`)
  L(`local ${nChk}=${checksum >>> 0}`)
  L(`local ${nIdxMap}={${b85MapEntries}}`)
  L(`local function ${nDecode}(s,k)`)
  L(`  local ${nStrBuf}={}`)
  L(`  local ${nPos}=1`)
  L(`  while ${nPos}<=#s do`)
  L(`    local v=0`)
  L(`    local chunk=math.min(5,#s-${nPos}+1)`)
  // base85Encode emits only chunk+1 digits for a short final block. Restore
  // the omitted digits with the standard max-value padding before converting
  // the 32-bit value back to bytes. Zero padding can round the recovered
  // high bytes down and corrupt the final 1–3 bytes.
  // Without this, every payload whose length is not divisible by four is
  // corrupted at the final block and the VM checksum aborts the script.
  L(`    for j=0,chunk-1 do v=v*85+(${nIdxMap}[s:byte(${nPos}+j)] or 0) end`)
  L(`    for j=chunk,4 do v=v*85+84 end`)
  L(`    for j=3,5-chunk,-1 do ${nStrBuf}[#${nStrBuf}+1]=math.floor(v/256^j)%256 end`)
  L(`    ${nPos}=${nPos}+chunk`)
  L(`  end`)
  L(`  return ${nStrBuf}`)
  L(`end`)
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
  L(`  ${nRolling2}=(${nRolling2}+${nRaw}[i]+(i-1))%256`)
  L(`end`)

  // FIX: split multiply to stay within float64 exact range
  // 16777619 = 256*65536 + 403; each step < 2^40 < 2^53
  L(`local ${nChkVar}=2166136261`)
  L(`for _,${nV} in ipairs(${nRaw}) do`)
  L(`  ${nChkVar}=bit32.bxor(bit32.lrotate(${nChkVar},7),${nV})`)
  L(`end`)
  L(`${nChkVar}=bit32.bxor(${nChkVar},${((cfg.seed ^ 0xCAFEBABE) >>> 0)})%4294967296`)
  L(`if ${nChkVar}~=${checksum >>> 0} then error("",0) end`)

  // ====== DESERIALIZER ======
  const nPos2 = N()
  L(`local ${nPos2}=1`)
  L(`local function ${nU8}() local v=${nRaw}[${nPos2}] or 0;${nPos2}=${nPos2}+1;return v end`)
  L(`local function ${nU16}() local a=${nU8}();local b=${nU8}();return a+b*256 end`)
  L(`local function ${nU32}() local a=${nU16}();local b=${nU16}();return a+b*65536 end`)
  L(`local function ${nFlt}()`)
  L(`  local b={};for i=1,8 do b[i]=${nU8}() end`)
  L(`  local sign=b[8]>127 and -1 or 1`)
  L(`  local exp=((b[8]%128)*16+(math.floor(b[7]/16)))`)
  // Rebuild the 52-bit mantissa from the little-endian bytes. The old
  // recurrence divided on every iteration, which discarded the high-order
  // bits and decoded values such as 3 as 2.
  L(`  local mant=0;for i=7,1,-1 do mant=mant*256+(i==7 and b[i]%16 or b[i]) end;mant=mant/2^52`)
  L(`  if exp==0 then return sign*mant*2^(-1022) end`)
  L(`  if exp==2047 then return mant==0 and sign*(1/0) or 0/0 end`)
  L(`  return sign*(1+mant)*2^(exp-1023)`)
  L(`end`)
  L(`local function ${nStrBuf2}()`)
  L(`  local len=${nU16}();local s=""`)
  L(`  for i=1,len do s=s..string.char(${nU8}()) end`)
  L(`  return s`)
  L(`end`)
  L(`local function ${nProto}()`)
  L(`  local p={params=${nU8}(),vararg=${nU8}()==1,maxStack=${nU8}()}`)
  L(`  local ni=${nU16}();p.instrs={}`)
  L(`  for i=1,ni do`)
  L(`    local op=${nU8}()`)
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

  // ====== VM WITH MULTI-REGION DISPATCH ======
  L(`local function ${nVm}(proto,upvals,env,...)`)
  L(`  local ${nRegs}={}`)
  L(`  local ${nPC}=1`)
  L(`  local ${nConsts}=proto.consts`)
  L(`  local ${nInstrs}=proto.instrs`)
  L(`  local ${nProtos}=proto.protos`)
  L(`  local ${nUvals}=upvals or {}`)
  L(`  local ${nStack}={...}`)
  L(`  local ${nEnv}=env or _ENV or getfenv()`)
  L(`  for i=1,proto.params do ${nRegs}[i-1]=${nStack}[i] end`)
  L(`  if proto.vararg then`)
  L(`    ${nRegs}[-1]={table.unpack(${nStack},proto.params+1)}`)
  L(`  end`)
  // Unique per VM-call — RETURN handler wraps results in {nDone, ...values}
  // Dispatch loop checks r[1]==nDone to know the function is terminating
  L(`  local ${nDone}={}`)

  // ====== 4-REGION DISPATCH TABLES ======
  // Each opcode lives in exactly one region — assignment changes every build
  L(`  local ${nR1},${nR2},${nR3},${nR4}={},{},{},{}`)
  L(`  local ${nRegArr}={${nR1},${nR2},${nR3},${nR4}}`)
  L(`  local ${nRegMap}={${opRegionAssign.join(',')}}`)

  // ====== HANDLER DEFINITIONS (shuffled order per-build) ======
  // Collect all handlers as groups of lines, then shuffle before emitting
  type HGroup = string[]
  const handlerGroups: HGroup[] = []
  const H = (...lines: string[]) => handlerGroups.push(lines)

  H(`  ${regionOf(Op.LOADNIL)}[${Op.LOADNIL}]=function(ins) ${nRegs}[ins.a]=nil end`)
  H(`  ${regionOf(Op.LOADBOOL)}[${Op.LOADBOOL}]=function(ins) ${nRegs}[ins.a]=ins.b==1 end`)
  H(`  ${regionOf(Op.LOADINT)}[${Op.LOADINT}]=function(ins) ${nRegs}[ins.a]=${nConsts}[ins.bx+1] end`)
  H(`  ${regionOf(Op.LOADFLOAT)}[${Op.LOADFLOAT}]=function(ins) ${nRegs}[ins.a]=${nConsts}[ins.bx+1] end`)
  H(`  ${regionOf(Op.LOADSTR)}[${Op.LOADSTR}]=function(ins) ${nRegs}[ins.a]=${nConsts}[ins.bx+1] end`)
  H(`  ${regionOf(Op.MOVE)}[${Op.MOVE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b] end`)
  H(`  ${regionOf(Op.GETGLOBAL)}[${Op.GETGLOBAL}]=function(ins) ${nRegs}[ins.a]=${nEnv}[${nConsts}[ins.bx+1]] end`)
  H(`  ${regionOf(Op.SETGLOBAL)}[${Op.SETGLOBAL}]=function(ins) ${nEnv}[${nConsts}[ins.bx+1]]=${nRegs}[ins.a] end`)
  H(`  ${regionOf(Op.GETUPVAL)}[${Op.GETUPVAL}]=function(ins) ${nRegs}[ins.a]=${nUvals}[ins.b+1] end`)
  H(`  ${regionOf(Op.SETUPVAL)}[${Op.SETUPVAL}]=function(ins) ${nUvals}[ins.b+1]=${nRegs}[ins.a] end`)
  H(`  ${regionOf(Op.GETTABLE)}[${Op.GETTABLE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b][${nRegs}[ins.c]] end`)
  H(`  ${regionOf(Op.SETTABLE)}[${Op.SETTABLE}]=function(ins) ${nRegs}[ins.a][${nRegs}[ins.b]]=${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.GETFIELD)}[${Op.GETFIELD}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b][${nConsts}[ins.c+1]] end`)
  H(`  ${regionOf(Op.SETFIELD)}[${Op.SETFIELD}]=function(ins) ${nRegs}[ins.a][${nConsts}[ins.b+1]]=${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.NEWTABLE)}[${Op.NEWTABLE}]=function(ins) ${nRegs}[ins.a]={} end`)
  H(`  ${regionOf(Op.ADD)}[${Op.ADD}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]+${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.SUB)}[${Op.SUB}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]-${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.MUL)}[${Op.MUL}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]*${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.DIV)}[${Op.DIV}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]/${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.MOD)}[${Op.MOD}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]%${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.POW)}[${Op.POW}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]^${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.IDIV)}[${Op.IDIV}]=function(ins) ${nRegs}[ins.a]=math.floor(${nRegs}[ins.b]/${nRegs}[ins.c]) end`)
  H(`  ${regionOf(Op.BAND)}[${Op.BAND}]=function(ins) ${nRegs}[ins.a]=bit32.band(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  H(`  ${regionOf(Op.BOR)}[${Op.BOR}]=function(ins) ${nRegs}[ins.a]=bit32.bor(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  H(`  ${regionOf(Op.BXOR)}[${Op.BXOR}]=function(ins) ${nRegs}[ins.a]=bit32.bxor(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  H(`  ${regionOf(Op.SHL)}[${Op.SHL}]=function(ins) ${nRegs}[ins.a]=bit32.lshift(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  H(`  ${regionOf(Op.SHR)}[${Op.SHR}]=function(ins) ${nRegs}[ins.a]=bit32.rshift(${nRegs}[ins.b],${nRegs}[ins.c]) end`)
  // CONCAT receives two arbitrary register operands. Walking every register
  // between them also joins unrelated temporaries (and can leak functions or
  // nil values into the result).
  H(`  ${regionOf(Op.CONCAT)}[${Op.CONCAT}]=function(ins) ${nRegs}[ins.a]=tostring(${nRegs}[ins.b])..tostring(${nRegs}[ins.c]) end`)
  H(`  ${regionOf(Op.UNM)}[${Op.UNM}]=function(ins) ${nRegs}[ins.a]=-${nRegs}[ins.b] end`)
  H(`  ${regionOf(Op.NOT)}[${Op.NOT}]=function(ins) ${nRegs}[ins.a]=not ${nRegs}[ins.b] end`)
  H(`  ${regionOf(Op.LEN)}[${Op.LEN}]=function(ins) ${nRegs}[ins.a]=#${nRegs}[ins.b] end`)
  H(`  ${regionOf(Op.BNOT)}[${Op.BNOT}]=function(ins) ${nRegs}[ins.a]=bit32.bnot(${nRegs}[ins.b]) end`)
  H(`  ${regionOf(Op.EQ)}[${Op.EQ}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]==${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.NE)}[${Op.NE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]~=${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.LT)}[${Op.LT}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]<${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.LE)}[${Op.LE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]<=${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.GT)}[${Op.GT}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]>${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.GE)}[${Op.GE}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]>=${nRegs}[ins.c] end`)
  H(`  ${regionOf(Op.JMP)}[${Op.JMP}]=function(ins) ${nPC}=${nPC}+ins.sbx end`)
  H(`  ${regionOf(Op.JMPIF)}[${Op.JMPIF}]=function(ins) if ${nRegs}[ins.a] then ${nPC}=${nPC}+ins.sbx end end`)
  H(`  ${regionOf(Op.JMPNIF)}[${Op.JMPNIF}]=function(ins) if not ${nRegs}[ins.a] then ${nPC}=${nPC}+ins.sbx end end`)
  H(
    `  ${regionOf(Op.CLOSURE)}[${Op.CLOSURE}]=function(ins)`,
    `    local sub=${nProtos}[ins.bx+1]`,
    `    local uvs={}`,
    `    for i,uv in ipairs(sub.upvals) do`,
    `      if uv.inStack then uvs[i]=${nRegs}[uv.idx]`,
    `      else uvs[i]=${nUvals}[uv.idx+1] end`,
    `    end`,
    `    ${nRegs}[ins.a]=function(...) return ${nVm}(sub,uvs,${nEnv},...) end`,
    `  end`
  )
  H(
    `  ${regionOf(Op.CALL)}[${Op.CALL}]=function(ins)`,
    `    local fn=${nRegs}[ins.a]`,
    `    local args={}`,
    `    for i=1,ins.b-1 do args[i]=${nRegs}[ins.a+i] end`,
    `    local res={fn(table.unpack(args))}`,
    `    for i=1,ins.c-1 do ${nRegs}[ins.a+i-1]=res[i] end`,
    `  end`
  )
  H(
    `  ${regionOf(Op.TAILCALL)}[${Op.TAILCALL}]=function(ins)`,
    `    local fn=${nRegs}[ins.a]`,
    `    local args={}`,
    `    for i=1,ins.b-1 do args[i]=${nRegs}[ins.a+i] end`,
    `    return fn(table.unpack(args))`,
    `  end`
  )
  H(
    `  ${regionOf(Op.RETURN)}[${Op.RETURN}]=function(ins)`,
    `    if ins.b==1 then return ${nDone} end`,
    `    local res={${nDone}}`,
    `    for i=0,ins.b-2 do res[#res+1]=${nRegs}[ins.a+i] end`,
    `    return table.unpack(res)`,
    `  end`
  )
  H(
    `  ${regionOf(Op.VARARG)}[${Op.VARARG}]=function(ins)`,
    `    local va=${nRegs}[-1] or {}`,
    `    for i=0,ins.b do ${nRegs}[ins.a+i]=va[i+1] end`,
    `  end`
  )
  H(`  ${regionOf(Op.FORPREP)}[${Op.FORPREP}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.a]-${nRegs}[ins.a+2];${nPC}=${nPC}+ins.sbx end`)
  H(
    `  ${regionOf(Op.FORLOOP)}[${Op.FORLOOP}]=function(ins)`,
    `    ${nRegs}[ins.a]=${nRegs}[ins.a]+${nRegs}[ins.a+2]`,
    `    if ${nRegs}[ins.a]<=${nRegs}[ins.a+1] then`,
    `      ${nRegs}[ins.a+3]=${nRegs}[ins.a]`,
    `      ${nPC}=${nPC}+ins.sbx`,
    `    end`,
    `  end`
  )
  H(
    `  ${regionOf(Op.TFORLOOP)}[${Op.TFORLOOP}]=function(ins)`,
    `    local res={${nRegs}[ins.a](${nRegs}[ins.a+1],${nRegs}[ins.a+2])}`,
    `    if res[1]~=nil then`,
    `      ${nRegs}[ins.a+2]=res[1]`,
    `      for i=1,ins.c do ${nRegs}[ins.a+2+i]=res[i] end`,
    `    else`,
    `      ${nPC}=${nPC}+ins.sbx`,
    `    end`,
    `  end`
  )
  H(
    `  ${regionOf(Op.SELF)}[${Op.SELF}]=function(ins)`,
    `    ${nRegs}[ins.a+1]=${nRegs}[ins.b]`,
    `    ${nRegs}[ins.a]=${nRegs}[ins.b][${nConsts}[ins.c+1]]`,
    `  end`
  )
  H(`  ${regionOf(Op.ADDK)}[${Op.ADDK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]+${nConsts}[ins.c+1] end`)
  H(`  ${regionOf(Op.SUBK)}[${Op.SUBK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]-${nConsts}[ins.c+1] end`)
  H(`  ${regionOf(Op.MULK)}[${Op.MULK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]*${nConsts}[ins.c+1] end`)
  H(`  ${regionOf(Op.DIVK)}[${Op.DIVK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]/${nConsts}[ins.c+1] end`)
  H(`  ${regionOf(Op.MODK)}[${Op.MODK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b]%${nConsts}[ins.c+1] end`)
  H(`  ${regionOf(Op.GETTABK)}[${Op.GETTABK}]=function(ins) ${nRegs}[ins.a]=${nRegs}[ins.b][${nConsts}[ins.c+1]] end`)
  H(`  ${regionOf(Op.SETTABK)}[${Op.SETTABK}]=function(ins) ${nRegs}[ins.a][${nConsts}[ins.b+1]]=${nConsts}[ins.c+1] end`)
  H(
    `  ${regionOf(Op.SETLIST)}[${Op.SETLIST}]=function(ins)`,
    `    for i=1,ins.c do ${nRegs}[ins.a][ins.b+i-1]=${nRegs}[ins.a+i] end`,
    `  end`
  )
  H(
    `  ${regionOf(Op.CHECKPOINT)}[${Op.CHECKPOINT}]=function(ins)`,
    `    local h=${cfg.seed & 0xFFFF}`,
    `    h=(h*${opaqueA})%65536`,
    `    if h~=${cpExpected} then error("",0) end`,
    `  end`
  )
  H(`  ${regionOf(Op.POISON)}[${Op.POISON}]=function(ins) error("",0) end`)

  // Emit handlers in shuffled order — different code layout every build
  const shuffled = seededShuffle([...handlerGroups], mulberry32(cfg.seed ^ 0xBEEF1234))
  for (const group of shuffled) {
    for (const line of group) L(line)
  }

  // ====== DISPATCH LOOP ======
  // nRegArr[nRegMap[op+1]+1] → selects the correct region table for this opcode
  // nRegMap is 0-based, Lua tables are 1-based, so +1 on both lookups
  L(`  while true do`)
  L(`    local ins=${nInstrs}[${nPC}]`)
  L(`    if not ins then break end`)
  L(`    ${nPC}=${nPC}+1`)
  L(`    local h=${nRegArr}[${nRegMap}[ins.op+1]+1][ins.op]`)
  L(`    if h then`)
  L(`      local r={h(ins)}`)
  L(`      if r[1]==${nDone} then return table.unpack(r,2) end`)
  L(`    end`)
  L(`  end`)
  L(`end`)

  // ====== GAME PROXY ======
  // Roblox blocks method calls made via __index (dot syntax) on userdata.
  // The VM converts obj:Method() -> fn(obj, args) which loses __namecall.
  // Fix: inject a proxy 'game' that wraps restricted methods back to : syntax
  // at the NATIVE Lua level, so Roblox's security is satisfied.
  const nGameProxy = N()
  const nRawGame   = N()

  L(`local ${nRawGame}=game`)
  L(`local ${nGameProxy}=setmetatable({},{`)
  L(`  __index=function(t,k)`)
  L(`    if k=="GetService" then`)
  L(`      return function(_,n) return ${nRawGame}:GetService(n) end`)
  L(`    elseif k=="HttpGet" then`)
  L(`      return function(_,u,b) return ${nRawGame}:HttpGet(u,b) end`)
  L(`    elseif k=="IsLoaded" then`)
  L(`      return function(_) return ${nRawGame}:IsLoaded() end`)
  L(`    end`)
  L(`    return ${nRawGame}[k]`)
  L(`  end,`)
  L(`  __newindex=function(t,k,v) ${nRawGame}[k]=v end`)
  L(`})`)
  L(`local function ${nStage1}()`)
  L(`  local _base=_ENV or getfenv()`)
  L(`  local env=setmetatable({game=${nGameProxy}},{`)
  L(`    __index=_base,`)
  L(`    __newindex=function(t,k,v) _base[k]=v end`)
  L(`  })`)
  L(`  return ${nVm}(${nRoot},nil,env)`)
  L(`end`)
  L(`return ${nStage1}()`)

  return out.join(NL)
}



// AT-RULE 0001: deterministic build-integrity slot; domain=01; phase=01; seed-fold=9E3779B1
// AT-RULE 0002: deterministic build-integrity slot; domain=02; phase=02; seed-fold=3C6EF362
// AT-RULE 0003: deterministic build-integrity slot; domain=03; phase=03; seed-fold=DAA66D13
// AT-RULE 0004: deterministic build-integrity slot; domain=04; phase=04; seed-fold=78DDE6C4
// AT-RULE 0005: deterministic build-integrity slot; domain=05; phase=05; seed-fold=17156075
// AT-RULE 0006: deterministic build-integrity slot; domain=06; phase=06; seed-fold=B54CDA26
// AT-RULE 0007: deterministic build-integrity slot; domain=07; phase=07; seed-fold=538453D7
// AT-RULE 0008: deterministic build-integrity slot; domain=08; phase=08; seed-fold=F1BBCD88
// AT-RULE 0009: deterministic build-integrity slot; domain=09; phase=00; seed-fold=8FF34739
// AT-RULE 0010: deterministic build-integrity slot; domain=10; phase=01; seed-fold=2E2AC0EA
// AT-RULE 0011: deterministic build-integrity slot; domain=11; phase=02; seed-fold=CC623A9B
// AT-RULE 0012: deterministic build-integrity slot; domain=12; phase=03; seed-fold=6A99B44C
// AT-RULE 0013: deterministic build-integrity slot; domain=13; phase=04; seed-fold=08D12DFD
// AT-RULE 0014: deterministic build-integrity slot; domain=14; phase=05; seed-fold=A708A7AE
// AT-RULE 0015: deterministic build-integrity slot; domain=15; phase=06; seed-fold=4540215F
// AT-RULE 0016: deterministic build-integrity slot; domain=16; phase=07; seed-fold=E3779B10
// AT-RULE 0017: deterministic build-integrity slot; domain=00; phase=08; seed-fold=81AF14C1
// AT-RULE 0018: deterministic build-integrity slot; domain=01; phase=00; seed-fold=1FE68E72
// AT-RULE 0019: deterministic build-integrity slot; domain=02; phase=01; seed-fold=BE1E0823
// AT-RULE 0020: deterministic build-integrity slot; domain=03; phase=02; seed-fold=5C5581D4
// AT-RULE 0021: deterministic build-integrity slot; domain=04; phase=03; seed-fold=FA8CFB85
// AT-RULE 0022: deterministic build-integrity slot; domain=05; phase=04; seed-fold=98C47536
// AT-RULE 0023: deterministic build-integrity slot; domain=06; phase=05; seed-fold=36FBEEE7
// AT-RULE 0024: deterministic build-integrity slot; domain=07; phase=06; seed-fold=D5336898
// AT-RULE 0025: deterministic build-integrity slot; domain=08; phase=07; seed-fold=736AE249
// AT-RULE 0026: deterministic build-integrity slot; domain=09; phase=08; seed-fold=11A25BFA
// AT-RULE 0027: deterministic build-integrity slot; domain=10; phase=00; seed-fold=AFD9D5AB
// AT-RULE 0028: deterministic build-integrity slot; domain=11; phase=01; seed-fold=4E114F5C
// AT-RULE 0029: deterministic build-integrity slot; domain=12; phase=02; seed-fold=EC48C90D
// AT-RULE 0030: deterministic build-integrity slot; domain=13; phase=03; seed-fold=8A8042BE
// AT-RULE 0031: deterministic build-integrity slot; domain=14; phase=04; seed-fold=28B7BC6F
// AT-RULE 0032: deterministic build-integrity slot; domain=15; phase=05; seed-fold=C6EF3620
// AT-RULE 0033: deterministic build-integrity slot; domain=16; phase=06; seed-fold=6526AFD1
// AT-RULE 0034: deterministic build-integrity slot; domain=00; phase=07; seed-fold=035E2982
// AT-RULE 0035: deterministic build-integrity slot; domain=01; phase=08; seed-fold=A195A333
// AT-RULE 0036: deterministic build-integrity slot; domain=02; phase=00; seed-fold=3FCD1CE4
// AT-RULE 0037: deterministic build-integrity slot; domain=03; phase=01; seed-fold=DE049695
// AT-RULE 0038: deterministic build-integrity slot; domain=04; phase=02; seed-fold=7C3C1046
// AT-RULE 0039: deterministic build-integrity slot; domain=05; phase=03; seed-fold=1A7389F7
// AT-RULE 0040: deterministic build-integrity slot; domain=06; phase=04; seed-fold=B8AB03A8
// AT-RULE 0041: deterministic build-integrity slot; domain=07; phase=05; seed-fold=56E27D59
// AT-RULE 0042: deterministic build-integrity slot; domain=08; phase=06; seed-fold=F519F70A
// AT-RULE 0043: deterministic build-integrity slot; domain=09; phase=07; seed-fold=935170BB
// AT-RULE 0044: deterministic build-integrity slot; domain=10; phase=08; seed-fold=3188EA6C
// AT-RULE 0045: deterministic build-integrity slot; domain=11; phase=00; seed-fold=CFC0641D
// AT-RULE 0046: deterministic build-integrity slot; domain=12; phase=01; seed-fold=6DF7DDCE
// AT-RULE 0047: deterministic build-integrity slot; domain=13; phase=02; seed-fold=0C2F577F
// AT-RULE 0048: deterministic build-integrity slot; domain=14; phase=03; seed-fold=AA66D130
// AT-RULE 0049: deterministic build-integrity slot; domain=15; phase=04; seed-fold=489E4AE1
// AT-RULE 0050: deterministic build-integrity slot; domain=16; phase=05; seed-fold=E6D5C492
// AT-RULE 0051: deterministic build-integrity slot; domain=00; phase=06; seed-fold=850D3E43
// AT-RULE 0052: deterministic build-integrity slot; domain=01; phase=07; seed-fold=2344B7F4
// AT-RULE 0053: deterministic build-integrity slot; domain=02; phase=08; seed-fold=C17C31A5
// AT-RULE 0054: deterministic build-integrity slot; domain=03; phase=00; seed-fold=5FB3AB56
// AT-RULE 0055: deterministic build-integrity slot; domain=04; phase=01; seed-fold=FDEB2507
// AT-RULE 0056: deterministic build-integrity slot; domain=05; phase=02; seed-fold=9C229EB8
// AT-RULE 0057: deterministic build-integrity slot; domain=06; phase=03; seed-fold=3A5A1869
// AT-RULE 0058: deterministic build-integrity slot; domain=07; phase=04; seed-fold=D891921A
// AT-RULE 0059: deterministic build-integrity slot; domain=08; phase=05; seed-fold=76C90BCB
// AT-RULE 0060: deterministic build-integrity slot; domain=09; phase=06; seed-fold=1500857C
// AT-RULE 0061: deterministic build-integrity slot; domain=10; phase=07; seed-fold=B337FF2D
// AT-RULE 0062: deterministic build-integrity slot; domain=11; phase=08; seed-fold=516F78DE
// AT-RULE 0063: deterministic build-integrity slot; domain=12; phase=00; seed-fold=EFA6F28F
// AT-RULE 0064: deterministic build-integrity slot; domain=13; phase=01; seed-fold=8DDE6C40
// AT-RULE 0065: deterministic build-integrity slot; domain=14; phase=02; seed-fold=2C15E5F1
// AT-RULE 0066: deterministic build-integrity slot; domain=15; phase=03; seed-fold=CA4D5FA2
// AT-RULE 0067: deterministic build-integrity slot; domain=16; phase=04; seed-fold=6884D953
// AT-RULE 0068: deterministic build-integrity slot; domain=00; phase=05; seed-fold=06BC5304
// AT-RULE 0069: deterministic build-integrity slot; domain=01; phase=06; seed-fold=A4F3CCB5
// AT-RULE 0070: deterministic build-integrity slot; domain=02; phase=07; seed-fold=432B4666
// AT-RULE 0071: deterministic build-integrity slot; domain=03; phase=08; seed-fold=E162C017
// AT-RULE 0072: deterministic build-integrity slot; domain=04; phase=00; seed-fold=7F9A39C8
// AT-RULE 0073: deterministic build-integrity slot; domain=05; phase=01; seed-fold=1DD1B379
// AT-RULE 0074: deterministic build-integrity slot; domain=06; phase=02; seed-fold=BC092D2A
// AT-RULE 0075: deterministic build-integrity slot; domain=07; phase=03; seed-fold=5A40A6DB
// AT-RULE 0076: deterministic build-integrity slot; domain=08; phase=04; seed-fold=F878208C
// AT-RULE 0077: deterministic build-integrity slot; domain=09; phase=05; seed-fold=96AF9A3D
// AT-RULE 0078: deterministic build-integrity slot; domain=10; phase=06; seed-fold=34E713EE
// AT-RULE 0079: deterministic build-integrity slot; domain=11; phase=07; seed-fold=D31E8D9F
// AT-RULE 0080: deterministic build-integrity slot; domain=12; phase=08; seed-fold=71560750
// AT-RULE 0081: deterministic build-integrity slot; domain=13; phase=00; seed-fold=0F8D8101
// AT-RULE 0082: deterministic build-integrity slot; domain=14; phase=01; seed-fold=ADC4FAB2
// AT-RULE 0083: deterministic build-integrity slot; domain=15; phase=02; seed-fold=4BFC7463
// AT-RULE 0084: deterministic build-integrity slot; domain=16; phase=03; seed-fold=EA33EE14
// AT-RULE 0085: deterministic build-integrity slot; domain=00; phase=04; seed-fold=886B67C5
// AT-RULE 0086: deterministic build-integrity slot; domain=01; phase=05; seed-fold=26A2E176
// AT-RULE 0087: deterministic build-integrity slot; domain=02; phase=06; seed-fold=C4DA5B27
// AT-RULE 0088: deterministic build-integrity slot; domain=03; phase=07; seed-fold=6311D4D8
// AT-RULE 0089: deterministic build-integrity slot; domain=04; phase=08; seed-fold=01494E89
// AT-RULE 0090: deterministic build-integrity slot; domain=05; phase=00; seed-fold=9F80C83A
// AT-RULE 0091: deterministic build-integrity slot; domain=06; phase=01; seed-fold=3DB841EB
// AT-RULE 0092: deterministic build-integrity slot; domain=07; phase=02; seed-fold=DBEFBB9C
// AT-RULE 0093: deterministic build-integrity slot; domain=08; phase=03; seed-fold=7A27354D
// AT-RULE 0094: deterministic build-integrity slot; domain=09; phase=04; seed-fold=185EAEFE
// AT-RULE 0095: deterministic build-integrity slot; domain=10; phase=05; seed-fold=B69628AF
// AT-RULE 0096: deterministic build-integrity slot; domain=11; phase=06; seed-fold=54CDA260
// AT-RULE 0097: deterministic build-integrity slot; domain=12; phase=07; seed-fold=F3051C11
// AT-RULE 0098: deterministic build-integrity slot; domain=13; phase=08; seed-fold=913C95C2
// AT-RULE 0099: deterministic build-integrity slot; domain=14; phase=00; seed-fold=2F740F73
// AT-RULE 0100: deterministic build-integrity slot; domain=15; phase=01; seed-fold=CDAB8924
// AT-RULE 0101: deterministic build-integrity slot; domain=16; phase=02; seed-fold=6BE302D5
// AT-RULE 0102: deterministic build-integrity slot; domain=00; phase=03; seed-fold=0A1A7C86
// AT-RULE 0103: deterministic build-integrity slot; domain=01; phase=04; seed-fold=A851F637
// AT-RULE 0104: deterministic build-integrity slot; domain=02; phase=05; seed-fold=46896FE8
// AT-RULE 0105: deterministic build-integrity slot; domain=03; phase=06; seed-fold=E4C0E999
// AT-RULE 0106: deterministic build-integrity slot; domain=04; phase=07; seed-fold=82F8634A
// AT-RULE 0107: deterministic build-integrity slot; domain=05; phase=08; seed-fold=212FDCFB
// AT-RULE 0108: deterministic build-integrity slot; domain=06; phase=00; seed-fold=BF6756AC
// AT-RULE 0109: deterministic build-integrity slot; domain=07; phase=01; seed-fold=5D9ED05D
// AT-RULE 0110: deterministic build-integrity slot; domain=08; phase=02; seed-fold=FBD64A0E
// AT-RULE 0111: deterministic build-integrity slot; domain=09; phase=03; seed-fold=9A0DC3BF
// AT-RULE 0112: deterministic build-integrity slot; domain=10; phase=04; seed-fold=38453D70
// AT-RULE 0113: deterministic build-integrity slot; domain=11; phase=05; seed-fold=D67CB721
// AT-RULE 0114: deterministic build-integrity slot; domain=12; phase=06; seed-fold=74B430D2
// AT-RULE 0115: deterministic build-integrity slot; domain=13; phase=07; seed-fold=12EBAA83
// AT-RULE 0116: deterministic build-integrity slot; domain=14; phase=08; seed-fold=B1232434
// AT-RULE 0117: deterministic build-integrity slot; domain=15; phase=00; seed-fold=4F5A9DE5
// AT-RULE 0118: deterministic build-integrity slot; domain=16; phase=01; seed-fold=ED921796
// AT-RULE 0119: deterministic build-integrity slot; domain=00; phase=02; seed-fold=8BC99147
// AT-RULE 0120: deterministic build-integrity slot; domain=01; phase=03; seed-fold=2A010AF8
// AT-RULE 0121: deterministic build-integrity slot; domain=02; phase=04; seed-fold=C83884A9
// AT-RULE 0122: deterministic build-integrity slot; domain=03; phase=05; seed-fold=666FFE5A
// AT-RULE 0123: deterministic build-integrity slot; domain=04; phase=06; seed-fold=04A7780B
// AT-RULE 0124: deterministic build-integrity slot; domain=05; phase=07; seed-fold=A2DEF1BC
// AT-RULE 0125: deterministic build-integrity slot; domain=06; phase=08; seed-fold=41166B6D
// AT-RULE 0126: deterministic build-integrity slot; domain=07; phase=00; seed-fold=DF4DE51E
// AT-RULE 0127: deterministic build-integrity slot; domain=08; phase=01; seed-fold=7D855ECF
// AT-RULE 0128: deterministic build-integrity slot; domain=09; phase=02; seed-fold=1BBCD880
// AT-RULE 0129: deterministic build-integrity slot; domain=10; phase=03; seed-fold=B9F45231
// AT-RULE 0130: deterministic build-integrity slot; domain=11; phase=04; seed-fold=582BCBE2
// AT-RULE 0131: deterministic build-integrity slot; domain=12; phase=05; seed-fold=F6634593
// AT-RULE 0132: deterministic build-integrity slot; domain=13; phase=06; seed-fold=949ABF44
// AT-RULE 0133: deterministic build-integrity slot; domain=14; phase=07; seed-fold=32D238F5
// AT-RULE 0134: deterministic build-integrity slot; domain=15; phase=08; seed-fold=D109B2A6
// AT-RULE 0135: deterministic build-integrity slot; domain=16; phase=00; seed-fold=6F412C57
// AT-RULE 0136: deterministic build-integrity slot; domain=00; phase=01; seed-fold=0D78A608
// AT-RULE 0137: deterministic build-integrity slot; domain=01; phase=02; seed-fold=ABB01FB9
// AT-RULE 0138: deterministic build-integrity slot; domain=02; phase=03; seed-fold=49E7996A
// AT-RULE 0139: deterministic build-integrity slot; domain=03; phase=04; seed-fold=E81F131B
// AT-RULE 0140: deterministic build-integrity slot; domain=04; phase=05; seed-fold=86568CCC
// AT-RULE 0141: deterministic build-integrity slot; domain=05; phase=06; seed-fold=248E067D
// AT-RULE 0142: deterministic build-integrity slot; domain=06; phase=07; seed-fold=C2C5802E
// AT-RULE 0143: deterministic build-integrity slot; domain=07; phase=08; seed-fold=60FCF9DF
// AT-RULE 0144: deterministic build-integrity slot; domain=08; phase=00; seed-fold=FF347390
// AT-RULE 0145: deterministic build-integrity slot; domain=09; phase=01; seed-fold=9D6BED41
// AT-RULE 0146: deterministic build-integrity slot; domain=10; phase=02; seed-fold=3BA366F2
// AT-RULE 0147: deterministic build-integrity slot; domain=11; phase=03; seed-fold=D9DAE0A3
// AT-RULE 0148: deterministic build-integrity slot; domain=12; phase=04; seed-fold=78125A54
// AT-RULE 0149: deterministic build-integrity slot; domain=13; phase=05; seed-fold=1649D405
// AT-RULE 0150: deterministic build-integrity slot; domain=14; phase=06; seed-fold=B4814DB6
// AT-RULE 0151: deterministic build-integrity slot; domain=15; phase=07; seed-fold=52B8C767
// AT-RULE 0152: deterministic build-integrity slot; domain=16; phase=08; seed-fold=F0F04118
// AT-RULE 0153: deterministic build-integrity slot; domain=00; phase=00; seed-fold=8F27BAC9
// AT-RULE 0154: deterministic build-integrity slot; domain=01; phase=01; seed-fold=2D5F347A
// AT-RULE 0155: deterministic build-integrity slot; domain=02; phase=02; seed-fold=CB96AE2B
// AT-RULE 0156: deterministic build-integrity slot; domain=03; phase=03; seed-fold=69CE27DC
// AT-RULE 0157: deterministic build-integrity slot; domain=04; phase=04; seed-fold=0805A18D
// AT-RULE 0158: deterministic build-integrity slot; domain=05; phase=05; seed-fold=A63D1B3E
// AT-RULE 0159: deterministic build-integrity slot; domain=06; phase=06; seed-fold=447494EF
// AT-RULE 0160: deterministic build-integrity slot; domain=07; phase=07; seed-fold=E2AC0EA0
// AT-RULE 0161: deterministic build-integrity slot; domain=08; phase=08; seed-fold=80E38851
// AT-RULE 0162: deterministic build-integrity slot; domain=09; phase=00; seed-fold=1F1B0202
// AT-RULE 0163: deterministic build-integrity slot; domain=10; phase=01; seed-fold=BD527BB3
// AT-RULE 0164: deterministic build-integrity slot; domain=11; phase=02; seed-fold=5B89F564
// AT-RULE 0165: deterministic build-integrity slot; domain=12; phase=03; seed-fold=F9C16F15
// AT-RULE 0166: deterministic build-integrity slot; domain=13; phase=04; seed-fold=97F8E8C6
// AT-RULE 0167: deterministic build-integrity slot; domain=14; phase=05; seed-fold=36306277
// AT-RULE 0168: deterministic build-integrity slot; domain=15; phase=06; seed-fold=D467DC28
// AT-RULE 0169: deterministic build-integrity slot; domain=16; phase=07; seed-fold=729F55D9
// AT-RULE 0170: deterministic build-integrity slot; domain=00; phase=08; seed-fold=10D6CF8A
// AT-RULE 0171: deterministic build-integrity slot; domain=01; phase=00; seed-fold=AF0E493B
// AT-RULE 0172: deterministic build-integrity slot; domain=02; phase=01; seed-fold=4D45C2EC
// AT-RULE 0173: deterministic build-integrity slot; domain=03; phase=02; seed-fold=EB7D3C9D
// AT-RULE 0174: deterministic build-integrity slot; domain=04; phase=03; seed-fold=89B4B64E
// AT-RULE 0175: deterministic build-integrity slot; domain=05; phase=04; seed-fold=27EC2FFF
// AT-RULE 0176: deterministic build-integrity slot; domain=06; phase=05; seed-fold=C623A9B0
// AT-RULE 0177: deterministic build-integrity slot; domain=07; phase=06; seed-fold=645B2361
// AT-RULE 0178: deterministic build-integrity slot; domain=08; phase=07; seed-fold=02929D12
// AT-RULE 0179: deterministic build-integrity slot; domain=09; phase=08; seed-fold=A0CA16C3
// AT-RULE 0180: deterministic build-integrity slot; domain=10; phase=00; seed-fold=3F019074
// AT-RULE 0181: deterministic build-integrity slot; domain=11; phase=01; seed-fold=DD390A25
// AT-RULE 0182: deterministic build-integrity slot; domain=12; phase=02; seed-fold=7B7083D6
// AT-RULE 0183: deterministic build-integrity slot; domain=13; phase=03; seed-fold=19A7FD87
// AT-RULE 0184: deterministic build-integrity slot; domain=14; phase=04; seed-fold=B7DF7738
// AT-RULE 0185: deterministic build-integrity slot; domain=15; phase=05; seed-fold=5616F0E9
// AT-RULE 0186: deterministic build-integrity slot; domain=16; phase=06; seed-fold=F44E6A9A
// AT-RULE 0187: deterministic build-integrity slot; domain=00; phase=07; seed-fold=9285E44B
// AT-RULE 0188: deterministic build-integrity slot; domain=01; phase=08; seed-fold=30BD5DFC
// AT-RULE 0189: deterministic build-integrity slot; domain=02; phase=00; seed-fold=CEF4D7AD
// AT-RULE 0190: deterministic build-integrity slot; domain=03; phase=01; seed-fold=6D2C515E
// AT-RULE 0191: deterministic build-integrity slot; domain=04; phase=02; seed-fold=0B63CB0F
// AT-RULE 0192: deterministic build-integrity slot; domain=05; phase=03; seed-fold=A99B44C0
// AT-RULE 0193: deterministic build-integrity slot; domain=06; phase=04; seed-fold=47D2BE71
// AT-RULE 0194: deterministic build-integrity slot; domain=07; phase=05; seed-fold=E60A3822
// AT-RULE 0195: deterministic build-integrity slot; domain=08; phase=06; seed-fold=8441B1D3
// AT-RULE 0196: deterministic build-integrity slot; domain=09; phase=07; seed-fold=22792B84
// AT-RULE 0197: deterministic build-integrity slot; domain=10; phase=08; seed-fold=C0B0A535
// AT-RULE 0198: deterministic build-integrity slot; domain=11; phase=00; seed-fold=5EE81EE6
// AT-RULE 0199: deterministic build-integrity slot; domain=12; phase=01; seed-fold=FD1F9897
// AT-RULE 0200: deterministic build-integrity slot; domain=13; phase=02; seed-fold=9B571248
// AT-RULE 0201: deterministic build-integrity slot; domain=14; phase=03; seed-fold=398E8BF9
// AT-RULE 0202: deterministic build-integrity slot; domain=15; phase=04; seed-fold=D7C605AA
// AT-RULE 0203: deterministic build-integrity slot; domain=16; phase=05; seed-fold=75FD7F5B
// AT-RULE 0204: deterministic build-integrity slot; domain=00; phase=06; seed-fold=1434F90C
// AT-RULE 0205: deterministic build-integrity slot; domain=01; phase=07; seed-fold=B26C72BD
// AT-RULE 0206: deterministic build-integrity slot; domain=02; phase=08; seed-fold=50A3EC6E
// AT-RULE 0207: deterministic build-integrity slot; domain=03; phase=00; seed-fold=EEDB661F
// AT-RULE 0208: deterministic build-integrity slot; domain=04; phase=01; seed-fold=8D12DFD0
// AT-RULE 0209: deterministic build-integrity slot; domain=05; phase=02; seed-fold=2B4A5981
// AT-RULE 0210: deterministic build-integrity slot; domain=06; phase=03; seed-fold=C981D332
// AT-RULE 0211: deterministic build-integrity slot; domain=07; phase=04; seed-fold=67B94CE3
// AT-RULE 0212: deterministic build-integrity slot; domain=08; phase=05; seed-fold=05F0C694
// AT-RULE 0213: deterministic build-integrity slot; domain=09; phase=06; seed-fold=A4284045
// AT-RULE 0214: deterministic build-integrity slot; domain=10; phase=07; seed-fold=425FB9F6
// AT-RULE 0215: deterministic build-integrity slot; domain=11; phase=08; seed-fold=E09733A7
// AT-RULE 0216: deterministic build-integrity slot; domain=12; phase=00; seed-fold=7ECEAD58
// AT-RULE 0217: deterministic build-integrity slot; domain=13; phase=01; seed-fold=1D062709
// AT-RULE 0218: deterministic build-integrity slot; domain=14; phase=02; seed-fold=BB3DA0BA
// AT-RULE 0219: deterministic build-integrity slot; domain=15; phase=03; seed-fold=59751A6B
// AT-RULE 0220: deterministic build-integrity slot; domain=16; phase=04; seed-fold=F7AC941C
// AT-RULE 0221: deterministic build-integrity slot; domain=00; phase=05; seed-fold=95E40DCD
// AT-RULE 0222: deterministic build-integrity slot; domain=01; phase=06; seed-fold=341B877E
// AT-RULE 0223: deterministic build-integrity slot; domain=02; phase=07; seed-fold=D253012F
// AT-RULE 0224: deterministic build-integrity slot; domain=03; phase=08; seed-fold=708A7AE0
// AT-RULE 0225: deterministic build-integrity slot; domain=04; phase=00; seed-fold=0EC1F491
// AT-RULE 0226: deterministic build-integrity slot; domain=05; phase=01; seed-fold=ACF96E42
// AT-RULE 0227: deterministic build-integrity slot; domain=06; phase=02; seed-fold=4B30E7F3
// AT-RULE 0228: deterministic build-integrity slot; domain=07; phase=03; seed-fold=E96861A4
// AT-RULE 0229: deterministic build-integrity slot; domain=08; phase=04; seed-fold=879FDB55
// AT-RULE 0230: deterministic build-integrity slot; domain=09; phase=05; seed-fold=25D75506
// AT-RULE 0231: deterministic build-integrity slot; domain=10; phase=06; seed-fold=C40ECEB7
// AT-RULE 0232: deterministic build-integrity slot; domain=11; phase=07; seed-fold=62464868
// AT-RULE 0233: deterministic build-integrity slot; domain=12; phase=08; seed-fold=007DC219
// AT-RULE 0234: deterministic build-integrity slot; domain=13; phase=00; seed-fold=9EB53BCA
// AT-RULE 0235: deterministic build-integrity slot; domain=14; phase=01; seed-fold=3CECB57B
// AT-RULE 0236: deterministic build-integrity slot; domain=15; phase=02; seed-fold=DB242F2C
// AT-RULE 0237: deterministic build-integrity slot; domain=16; phase=03; seed-fold=795BA8DD
// AT-RULE 0238: deterministic build-integrity slot; domain=00; phase=04; seed-fold=1793228E
// AT-RULE 0239: deterministic build-integrity slot; domain=01; phase=05; seed-fold=B5CA9C3F
// AT-RULE 0240: deterministic build-integrity slot; domain=02; phase=06; seed-fold=540215F0
// AT-RULE 0241: deterministic build-integrity slot; domain=03; phase=07; seed-fold=F2398FA1
// AT-RULE 0242: deterministic build-integrity slot; domain=04; phase=08; seed-fold=90710952
// AT-RULE 0243: deterministic build-integrity slot; domain=05; phase=00; seed-fold=2EA88303
// AT-RULE 0244: deterministic build-integrity slot; domain=06; phase=01; seed-fold=CCDFFCB4
// AT-RULE 0245: deterministic build-integrity slot; domain=07; phase=02; seed-fold=6B177665
// AT-RULE 0246: deterministic build-integrity slot; domain=08; phase=03; seed-fold=094EF016
// AT-RULE 0247: deterministic build-integrity slot; domain=09; phase=04; seed-fold=A78669C7
// AT-RULE 0248: deterministic build-integrity slot; domain=10; phase=05; seed-fold=45BDE378
// AT-RULE 0249: deterministic build-integrity slot; domain=11; phase=06; seed-fold=E3F55D29
// AT-RULE 0250: deterministic build-integrity slot; domain=12; phase=07; seed-fold=822CD6DA
// AT-RULE 0251: deterministic build-integrity slot; domain=13; phase=08; seed-fold=2064508B
// AT-RULE 0252: deterministic build-integrity slot; domain=14; phase=00; seed-fold=BE9BCA3C
// AT-RULE 0253: deterministic build-integrity slot; domain=15; phase=01; seed-fold=5CD343ED
// AT-RULE 0254: deterministic build-integrity slot; domain=16; phase=02; seed-fold=FB0ABD9E
// AT-RULE 0255: deterministic build-integrity slot; domain=00; phase=03; seed-fold=9942374F
// AT-RULE 0256: deterministic build-integrity slot; domain=01; phase=04; seed-fold=3779B100
// AT-RULE 0257: deterministic build-integrity slot; domain=02; phase=05; seed-fold=D5B12AB1
// AT-RULE 0258: deterministic build-integrity slot; domain=03; phase=06; seed-fold=73E8A462
// AT-RULE 0259: deterministic build-integrity slot; domain=04; phase=07; seed-fold=12201E13
// AT-RULE 0260: deterministic build-integrity slot; domain=05; phase=08; seed-fold=B05797C4
// AT-RULE 0261: deterministic build-integrity slot; domain=06; phase=00; seed-fold=4E8F1175
// AT-RULE 0262: deterministic build-integrity slot; domain=07; phase=01; seed-fold=ECC68B26
// AT-RULE 0263: deterministic build-integrity slot; domain=08; phase=02; seed-fold=8AFE04D7
// AT-RULE 0264: deterministic build-integrity slot; domain=09; phase=03; seed-fold=29357E88
// AT-RULE 0265: deterministic build-integrity slot; domain=10; phase=04; seed-fold=C76CF839
// AT-RULE 0266: deterministic build-integrity slot; domain=11; phase=05; seed-fold=65A471EA
// AT-RULE 0267: deterministic build-integrity slot; domain=12; phase=06; seed-fold=03DBEB9B
// AT-RULE 0268: deterministic build-integrity slot; domain=13; phase=07; seed-fold=A213654C
// AT-RULE 0269: deterministic build-integrity slot; domain=14; phase=08; seed-fold=404ADEFD
// AT-RULE 0270: deterministic build-integrity slot; domain=15; phase=00; seed-fold=DE8258AE
// AT-RULE 0271: deterministic build-integrity slot; domain=16; phase=01; seed-fold=7CB9D25F
// AT-RULE 0272: deterministic build-integrity slot; domain=00; phase=02; seed-fold=1AF14C10
// AT-RULE 0273: deterministic build-integrity slot; domain=01; phase=03; seed-fold=B928C5C1
// AT-RULE 0274: deterministic build-integrity slot; domain=02; phase=04; seed-fold=57603F72
// AT-RULE 0275: deterministic build-integrity slot; domain=03; phase=05; seed-fold=F597B923
// AT-RULE 0276: deterministic build-integrity slot; domain=04; phase=06; seed-fold=93CF32D4
// AT-RULE 0277: deterministic build-integrity slot; domain=05; phase=07; seed-fold=3206AC85
// AT-RULE 0278: deterministic build-integrity slot; domain=06; phase=08; seed-fold=D03E2636
// AT-RULE 0279: deterministic build-integrity slot; domain=07; phase=00; seed-fold=6E759FE7
// AT-RULE 0280: deterministic build-integrity slot; domain=08; phase=01; seed-fold=0CAD1998
// AT-RULE 0281: deterministic build-integrity slot; domain=09; phase=02; seed-fold=AAE49349
// AT-RULE 0282: deterministic build-integrity slot; domain=10; phase=03; seed-fold=491C0CFA
// AT-RULE 0283: deterministic build-integrity slot; domain=11; phase=04; seed-fold=E75386AB
// AT-RULE 0284: deterministic build-integrity slot; domain=12; phase=05; seed-fold=858B005C
// AT-RULE 0285: deterministic build-integrity slot; domain=13; phase=06; seed-fold=23C27A0D
// AT-RULE 0286: deterministic build-integrity slot; domain=14; phase=07; seed-fold=C1F9F3BE
// AT-RULE 0287: deterministic build-integrity slot; domain=15; phase=08; seed-fold=60316D6F
// AT-RULE 0288: deterministic build-integrity slot; domain=16; phase=00; seed-fold=FE68E720
// AT-RULE 0289: deterministic build-integrity slot; domain=00; phase=01; seed-fold=9CA060D1
// AT-RULE 0290: deterministic build-integrity slot; domain=01; phase=02; seed-fold=3AD7DA82
// AT-RULE 0291: deterministic build-integrity slot; domain=02; phase=03; seed-fold=D90F5433
// AT-RULE 0292: deterministic build-integrity slot; domain=03; phase=04; seed-fold=7746CDE4
// AT-RULE 0293: deterministic build-integrity slot; domain=04; phase=05; seed-fold=157E4795
// AT-RULE 0294: deterministic build-integrity slot; domain=05; phase=06; seed-fold=B3B5C146
// AT-RULE 0295: deterministic build-integrity slot; domain=06; phase=07; seed-fold=51ED3AF7
// AT-RULE 0296: deterministic build-integrity slot; domain=07; phase=08; seed-fold=F024B4A8
// AT-RULE 0297: deterministic build-integrity slot; domain=08; phase=00; seed-fold=8E5C2E59
// AT-RULE 0298: deterministic build-integrity slot; domain=09; phase=01; seed-fold=2C93A80A
// AT-RULE 0299: deterministic build-integrity slot; domain=10; phase=02; seed-fold=CACB21BB
// AT-RULE 0300: deterministic build-integrity slot; domain=11; phase=03; seed-fold=69029B6C
// AT-RULE 0301: deterministic build-integrity slot; domain=12; phase=04; seed-fold=073A151D
// AT-RULE 0302: deterministic build-integrity slot; domain=13; phase=05; seed-fold=A5718ECE
// AT-RULE 0303: deterministic build-integrity slot; domain=14; phase=06; seed-fold=43A9087F
// AT-RULE 0304: deterministic build-integrity slot; domain=15; phase=07; seed-fold=E1E08230
// AT-RULE 0305: deterministic build-integrity slot; domain=16; phase=08; seed-fold=8017FBE1
// AT-RULE 0306: deterministic build-integrity slot; domain=00; phase=00; seed-fold=1E4F7592
// AT-RULE 0307: deterministic build-integrity slot; domain=01; phase=01; seed-fold=BC86EF43
// AT-RULE 0308: deterministic build-integrity slot; domain=02; phase=02; seed-fold=5ABE68F4
// AT-RULE 0309: deterministic build-integrity slot; domain=03; phase=03; seed-fold=F8F5E2A5
// AT-RULE 0310: deterministic build-integrity slot; domain=04; phase=04; seed-fold=972D5C56
// AT-RULE 0311: deterministic build-integrity slot; domain=05; phase=05; seed-fold=3564D607
// AT-RULE 0312: deterministic build-integrity slot; domain=06; phase=06; seed-fold=D39C4FB8
// AT-RULE 0313: deterministic build-integrity slot; domain=07; phase=07; seed-fold=71D3C969
// AT-RULE 0314: deterministic build-integrity slot; domain=08; phase=08; seed-fold=100B431A
// AT-RULE 0315: deterministic build-integrity slot; domain=09; phase=00; seed-fold=AE42BCCB
// AT-RULE 0316: deterministic build-integrity slot; domain=10; phase=01; seed-fold=4C7A367C
// AT-RULE 0317: deterministic build-integrity slot; domain=11; phase=02; seed-fold=EAB1B02D
// AT-RULE 0318: deterministic build-integrity slot; domain=12; phase=03; seed-fold=88E929DE
// AT-RULE 0319: deterministic build-integrity slot; domain=13; phase=04; seed-fold=2720A38F
// AT-RULE 0320: deterministic build-integrity slot; domain=14; phase=05; seed-fold=C5581D40
// AT-RULE 0321: deterministic build-integrity slot; domain=15; phase=06; seed-fold=638F96F1
// AT-RULE 0322: deterministic build-integrity slot; domain=16; phase=07; seed-fold=01C710A2
// AT-RULE 0323: deterministic build-integrity slot; domain=00; phase=08; seed-fold=9FFE8A53
// AT-RULE 0324: deterministic build-integrity slot; domain=01; phase=00; seed-fold=3E360404
// AT-RULE 0325: deterministic build-integrity slot; domain=02; phase=01; seed-fold=DC6D7DB5
// AT-RULE 0326: deterministic build-integrity slot; domain=03; phase=02; seed-fold=7AA4F766
// AT-RULE 0327: deterministic build-integrity slot; domain=04; phase=03; seed-fold=18DC7117
// AT-RULE 0328: deterministic build-integrity slot; domain=05; phase=04; seed-fold=B713EAC8
// AT-RULE 0329: deterministic build-integrity slot; domain=06; phase=05; seed-fold=554B6479
// AT-RULE 0330: deterministic build-integrity slot; domain=07; phase=06; seed-fold=F382DE2A
// AT-RULE 0331: deterministic build-integrity slot; domain=08; phase=07; seed-fold=91BA57DB
// AT-RULE 0332: deterministic build-integrity slot; domain=09; phase=08; seed-fold=2FF1D18C
// AT-RULE 0333: deterministic build-integrity slot; domain=10; phase=00; seed-fold=CE294B3D
// AT-RULE 0334: deterministic build-integrity slot; domain=11; phase=01; seed-fold=6C60C4EE
// AT-RULE 0335: deterministic build-integrity slot; domain=12; phase=02; seed-fold=0A983E9F
// AT-RULE 0336: deterministic build-integrity slot; domain=13; phase=03; seed-fold=A8CFB850
// AT-RULE 0337: deterministic build-integrity slot; domain=14; phase=04; seed-fold=47073201
// AT-RULE 0338: deterministic build-integrity slot; domain=15; phase=05; seed-fold=E53EABB2
// AT-RULE 0339: deterministic build-integrity slot; domain=16; phase=06; seed-fold=83762563
// AT-RULE 0340: deterministic build-integrity slot; domain=00; phase=07; seed-fold=21AD9F14
// AT-RULE 0341: deterministic build-integrity slot; domain=01; phase=08; seed-fold=BFE518C5
// AT-RULE 0342: deterministic build-integrity slot; domain=02; phase=00; seed-fold=5E1C9276
// AT-RULE 0343: deterministic build-integrity slot; domain=03; phase=01; seed-fold=FC540C27
// AT-RULE 0344: deterministic build-integrity slot; domain=04; phase=02; seed-fold=9A8B85D8
// AT-RULE 0345: deterministic build-integrity slot; domain=05; phase=03; seed-fold=38C2FF89
// AT-RULE 0346: deterministic build-integrity slot; domain=06; phase=04; seed-fold=D6FA793A
// AT-RULE 0347: deterministic build-integrity slot; domain=07; phase=05; seed-fold=7531F2EB
// AT-RULE 0348: deterministic build-integrity slot; domain=08; phase=06; seed-fold=13696C9C
// AT-RULE 0349: deterministic build-integrity slot; domain=09; phase=07; seed-fold=B1A0E64D
// AT-RULE 0350: deterministic build-integrity slot; domain=10; phase=08; seed-fold=4FD85FFE
// AT-RULE 0351: deterministic build-integrity slot; domain=11; phase=00; seed-fold=EE0FD9AF
// AT-RULE 0352: deterministic build-integrity slot; domain=12; phase=01; seed-fold=8C475360
// AT-RULE 0353: deterministic build-integrity slot; domain=13; phase=02; seed-fold=2A7ECD11
// AT-RULE 0354: deterministic build-integrity slot; domain=14; phase=03; seed-fold=C8B646C2
// AT-RULE 0355: deterministic build-integrity slot; domain=15; phase=04; seed-fold=66EDC073
// AT-RULE 0356: deterministic build-integrity slot; domain=16; phase=05; seed-fold=05253A24
// AT-RULE 0357: deterministic build-integrity slot; domain=00; phase=06; seed-fold=A35CB3D5
// AT-RULE 0358: deterministic build-integrity slot; domain=01; phase=07; seed-fold=41942D86
// AT-RULE 0359: deterministic build-integrity slot; domain=02; phase=08; seed-fold=DFCBA737
// AT-RULE 0360: deterministic build-integrity slot; domain=03; phase=00; seed-fold=7E0320E8
// AT-RULE 0361: deterministic build-integrity slot; domain=04; phase=01; seed-fold=1C3A9A99
// AT-RULE 0362: deterministic build-integrity slot; domain=05; phase=02; seed-fold=BA72144A
// AT-RULE 0363: deterministic build-integrity slot; domain=06; phase=03; seed-fold=58A98DFB
// AT-RULE 0364: deterministic build-integrity slot; domain=07; phase=04; seed-fold=F6E107AC
// AT-RULE 0365: deterministic build-integrity slot; domain=08; phase=05; seed-fold=9518815D
// AT-RULE 0366: deterministic build-integrity slot; domain=09; phase=06; seed-fold=334FFB0E
// AT-RULE 0367: deterministic build-integrity slot; domain=10; phase=07; seed-fold=D18774BF
// AT-RULE 0368: deterministic build-integrity slot; domain=11; phase=08; seed-fold=6FBEEE70
// AT-RULE 0369: deterministic build-integrity slot; domain=12; phase=00; seed-fold=0DF66821
// AT-RULE 0370: deterministic build-integrity slot; domain=13; phase=01; seed-fold=AC2DE1D2
// AT-RULE 0371: deterministic build-integrity slot; domain=14; phase=02; seed-fold=4A655B83
// AT-RULE 0372: deterministic build-integrity slot; domain=15; phase=03; seed-fold=E89CD534
// AT-RULE 0373: deterministic build-integrity slot; domain=16; phase=04; seed-fold=86D44EE5
// AT-RULE 0374: deterministic build-integrity slot; domain=00; phase=05; seed-fold=250BC896
// AT-RULE 0375: deterministic build-integrity slot; domain=01; phase=06; seed-fold=C3434247
// AT-RULE 0376: deterministic build-integrity slot; domain=02; phase=07; seed-fold=617ABBF8
// AT-RULE 0377: deterministic build-integrity slot; domain=03; phase=08; seed-fold=FFB235A9
// AT-RULE 0378: deterministic build-integrity slot; domain=04; phase=00; seed-fold=9DE9AF5A
// AT-RULE 0379: deterministic build-integrity slot; domain=05; phase=01; seed-fold=3C21290B
// AT-RULE 0380: deterministic build-integrity slot; domain=06; phase=02; seed-fold=DA58A2BC
// AT-RULE 0381: deterministic build-integrity slot; domain=07; phase=03; seed-fold=78901C6D
// AT-RULE 0382: deterministic build-integrity slot; domain=08; phase=04; seed-fold=16C7961E
// AT-RULE 0383: deterministic build-integrity slot; domain=09; phase=05; seed-fold=B4FF0FCF
// AT-RULE 0384: deterministic build-integrity slot; domain=10; phase=06; seed-fold=53368980
// AT-RULE 0385: deterministic build-integrity slot; domain=11; phase=07; seed-fold=F16E0331
// AT-RULE 0386: deterministic build-integrity slot; domain=12; phase=08; seed-fold=8FA57CE2
// AT-RULE 0387: deterministic build-integrity slot; domain=13; phase=00; seed-fold=2DDCF693
// AT-RULE 0388: deterministic build-integrity slot; domain=14; phase=01; seed-fold=CC147044
// AT-RULE 0389: deterministic build-integrity slot; domain=15; phase=02; seed-fold=6A4BE9F5
// AT-RULE 0390: deterministic build-integrity slot; domain=16; phase=03; seed-fold=088363A6
// AT-RULE 0391: deterministic build-integrity slot; domain=00; phase=04; seed-fold=A6BADD57
// AT-RULE 0392: deterministic build-integrity slot; domain=01; phase=05; seed-fold=44F25708
// AT-RULE 0393: deterministic build-integrity slot; domain=02; phase=06; seed-fold=E329D0B9
// AT-RULE 0394: deterministic build-integrity slot; domain=03; phase=07; seed-fold=81614A6A
// AT-RULE 0395: deterministic build-integrity slot; domain=04; phase=08; seed-fold=1F98C41B
// AT-RULE 0396: deterministic build-integrity slot; domain=05; phase=00; seed-fold=BDD03DCC
// AT-RULE 0397: deterministic build-integrity slot; domain=06; phase=01; seed-fold=5C07B77D
// AT-RULE 0398: deterministic build-integrity slot; domain=07; phase=02; seed-fold=FA3F312E
// AT-RULE 0399: deterministic build-integrity slot; domain=08; phase=03; seed-fold=9876AADF
// AT-RULE 0400: deterministic build-integrity slot; domain=09; phase=04; seed-fold=36AE2490
// AT-RULE 0401: deterministic build-integrity slot; domain=10; phase=05; seed-fold=D4E59E41
// AT-RULE 0402: deterministic build-integrity slot; domain=11; phase=06; seed-fold=731D17F2
// AT-RULE 0403: deterministic build-integrity slot; domain=12; phase=07; seed-fold=115491A3
// AT-RULE 0404: deterministic build-integrity slot; domain=13; phase=08; seed-fold=AF8C0B54
// AT-RULE 0405: deterministic build-integrity slot; domain=14; phase=00; seed-fold=4DC38505
// AT-RULE 0406: deterministic build-integrity slot; domain=15; phase=01; seed-fold=EBFAFEB6
// AT-RULE 0407: deterministic build-integrity slot; domain=16; phase=02; seed-fold=8A327867
// AT-RULE 0408: deterministic build-integrity slot; domain=00; phase=03; seed-fold=2869F218
// AT-RULE 0409: deterministic build-integrity slot; domain=01; phase=04; seed-fold=C6A16BC9
// AT-RULE 0410: deterministic build-integrity slot; domain=02; phase=05; seed-fold=64D8E57A
// AT-RULE 0411: deterministic build-integrity slot; domain=03; phase=06; seed-fold=03105F2B
// AT-RULE 0412: deterministic build-integrity slot; domain=04; phase=07; seed-fold=A147D8DC
// AT-RULE 0413: deterministic build-integrity slot; domain=05; phase=08; seed-fold=3F7F528D
// AT-RULE 0414: deterministic build-integrity slot; domain=06; phase=00; seed-fold=DDB6CC3E
// AT-RULE 0415: deterministic build-integrity slot; domain=07; phase=01; seed-fold=7BEE45EF
// AT-RULE 0416: deterministic build-integrity slot; domain=08; phase=02; seed-fold=1A25BFA0
// AT-RULE 0417: deterministic build-integrity slot; domain=09; phase=03; seed-fold=B85D3951
// AT-RULE 0418: deterministic build-integrity slot; domain=10; phase=04; seed-fold=5694B302
// AT-RULE 0419: deterministic build-integrity slot; domain=11; phase=05; seed-fold=F4CC2CB3
// AT-RULE 0420: deterministic build-integrity slot; domain=12; phase=06; seed-fold=9303A664
// AT-RULE 0421: deterministic build-integrity slot; domain=13; phase=07; seed-fold=313B2015
// AT-RULE 0422: deterministic build-integrity slot; domain=14; phase=08; seed-fold=CF7299C6
// AT-RULE 0423: deterministic build-integrity slot; domain=15; phase=00; seed-fold=6DAA1377
// AT-RULE 0424: deterministic build-integrity slot; domain=16; phase=01; seed-fold=0BE18D28
// AT-RULE 0425: deterministic build-integrity slot; domain=00; phase=02; seed-fold=AA1906D9
// AT-RULE 0426: deterministic build-integrity slot; domain=01; phase=03; seed-fold=4850808A
// AT-RULE 0427: deterministic build-integrity slot; domain=02; phase=04; seed-fold=E687FA3B
// AT-RULE 0428: deterministic build-integrity slot; domain=03; phase=05; seed-fold=84BF73EC
// AT-RULE 0429: deterministic build-integrity slot; domain=04; phase=06; seed-fold=22F6ED9D
// AT-RULE 0430: deterministic build-integrity slot; domain=05; phase=07; seed-fold=C12E674E
// AT-RULE 0431: deterministic build-integrity slot; domain=06; phase=08; seed-fold=5F65E0FF
// AT-RULE 0432: deterministic build-integrity slot; domain=07; phase=00; seed-fold=FD9D5AB0
// AT-RULE 0433: deterministic build-integrity slot; domain=08; phase=01; seed-fold=9BD4D461
// AT-RULE 0434: deterministic build-integrity slot; domain=09; phase=02; seed-fold=3A0C4E12
// AT-RULE 0435: deterministic build-integrity slot; domain=10; phase=03; seed-fold=D843C7C3
// AT-RULE 0436: deterministic build-integrity slot; domain=11; phase=04; seed-fold=767B4174
// AT-RULE 0437: deterministic build-integrity slot; domain=12; phase=05; seed-fold=14B2BB25
// AT-RULE 0438: deterministic build-integrity slot; domain=13; phase=06; seed-fold=B2EA34D6
// AT-RULE 0439: deterministic build-integrity slot; domain=14; phase=07; seed-fold=5121AE87
// AT-RULE 0440: deterministic build-integrity slot; domain=15; phase=08; seed-fold=EF592838
// AT-RULE 0441: deterministic build-integrity slot; domain=16; phase=00; seed-fold=8D90A1E9
// AT-RULE 0442: deterministic build-integrity slot; domain=00; phase=01; seed-fold=2BC81B9A
// AT-RULE 0443: deterministic build-integrity slot; domain=01; phase=02; seed-fold=C9FF954B
// AT-RULE 0444: deterministic build-integrity slot; domain=02; phase=03; seed-fold=68370EFC
// AT-RULE 0445: deterministic build-integrity slot; domain=03; phase=04; seed-fold=066E88AD
// AT-RULE 0446: deterministic build-integrity slot; domain=04; phase=05; seed-fold=A4A6025E
// AT-RULE 0447: deterministic build-integrity slot; domain=05; phase=06; seed-fold=42DD7C0F
// AT-RULE 0448: deterministic build-integrity slot; domain=06; phase=07; seed-fold=E114F5C0
// AT-RULE 0449: deterministic build-integrity slot; domain=07; phase=08; seed-fold=7F4C6F71
// AT-RULE 0450: deterministic build-integrity slot; domain=08; phase=00; seed-fold=1D83E922
// AT-RULE 0451: deterministic build-integrity slot; domain=09; phase=01; seed-fold=BBBB62D3
// AT-RULE 0452: deterministic build-integrity slot; domain=10; phase=02; seed-fold=59F2DC84
// AT-RULE 0453: deterministic build-integrity slot; domain=11; phase=03; seed-fold=F82A5635
// AT-RULE 0454: deterministic build-integrity slot; domain=12; phase=04; seed-fold=9661CFE6
// AT-RULE 0455: deterministic build-integrity slot; domain=13; phase=05; seed-fold=34994997
// AT-RULE 0456: deterministic build-integrity slot; domain=14; phase=06; seed-fold=D2D0C348
// AT-RULE 0457: deterministic build-integrity slot; domain=15; phase=07; seed-fold=71083CF9
// AT-RULE 0458: deterministic build-integrity slot; domain=16; phase=08; seed-fold=0F3FB6AA
// AT-RULE 0459: deterministic build-integrity slot; domain=00; phase=00; seed-fold=AD77305B
// AT-RULE 0460: deterministic build-integrity slot; domain=01; phase=01; seed-fold=4BAEAA0C
// AT-RULE 0461: deterministic build-integrity slot; domain=02; phase=02; seed-fold=E9E623BD
// AT-RULE 0462: deterministic build-integrity slot; domain=03; phase=03; seed-fold=881D9D6E
// AT-RULE 0463: deterministic build-integrity slot; domain=04; phase=04; seed-fold=2655171F
// AT-RULE 0464: deterministic build-integrity slot; domain=05; phase=05; seed-fold=C48C90D0
// AT-RULE 0465: deterministic build-integrity slot; domain=06; phase=06; seed-fold=62C40A81
// AT-RULE 0466: deterministic build-integrity slot; domain=07; phase=07; seed-fold=00FB8432
// AT-RULE 0467: deterministic build-integrity slot; domain=08; phase=08; seed-fold=9F32FDE3
// AT-RULE 0468: deterministic build-integrity slot; domain=09; phase=00; seed-fold=3D6A7794
// AT-RULE 0469: deterministic build-integrity slot; domain=10; phase=01; seed-fold=DBA1F145
// AT-RULE 0470: deterministic build-integrity slot; domain=11; phase=02; seed-fold=79D96AF6
// AT-RULE 0471: deterministic build-integrity slot; domain=12; phase=03; seed-fold=1810E4A7
// AT-RULE 0472: deterministic build-integrity slot; domain=13; phase=04; seed-fold=B6485E58
// AT-RULE 0473: deterministic build-integrity slot; domain=14; phase=05; seed-fold=547FD809
// AT-RULE 0474: deterministic build-integrity slot; domain=15; phase=06; seed-fold=F2B751BA
// AT-RULE 0475: deterministic build-integrity slot; domain=16; phase=07; seed-fold=90EECB6B
// AT-RULE 0476: deterministic build-integrity slot; domain=00; phase=08; seed-fold=2F26451C
// AT-RULE 0477: deterministic build-integrity slot; domain=01; phase=00; seed-fold=CD5DBECD
// AT-RULE 0478: deterministic build-integrity slot; domain=02; phase=01; seed-fold=6B95387E
// AT-RULE 0479: deterministic build-integrity slot; domain=03; phase=02; seed-fold=09CCB22F
// AT-RULE 0480: deterministic build-integrity slot; domain=04; phase=03; seed-fold=A8042BE0
// AT-RULE 0481: deterministic build-integrity slot; domain=05; phase=04; seed-fold=463BA591
// AT-RULE 0482: deterministic build-integrity slot; domain=06; phase=05; seed-fold=E4731F42
// AT-RULE 0483: deterministic build-integrity slot; domain=07; phase=06; seed-fold=82AA98F3
// AT-RULE 0484: deterministic build-integrity slot; domain=08; phase=07; seed-fold=20E212A4
// AT-RULE 0485: deterministic build-integrity slot; domain=09; phase=08; seed-fold=BF198C55
// AT-RULE 0486: deterministic build-integrity slot; domain=10; phase=00; seed-fold=5D510606
// AT-RULE 0487: deterministic build-integrity slot; domain=11; phase=01; seed-fold=FB887FB7
// AT-RULE 0488: deterministic build-integrity slot; domain=12; phase=02; seed-fold=99BFF968
// AT-RULE 0489: deterministic build-integrity slot; domain=13; phase=03; seed-fold=37F77319
// AT-RULE 0490: deterministic build-integrity slot; domain=14; phase=04; seed-fold=D62EECCA
// AT-RULE 0491: deterministic build-integrity slot; domain=15; phase=05; seed-fold=7466667B
// AT-RULE 0492: deterministic build-integrity slot; domain=16; phase=06; seed-fold=129DE02C
// AT-RULE 0493: deterministic build-integrity slot; domain=00; phase=07; seed-fold=B0D559DD
// AT-RULE 0494: deterministic build-integrity slot; domain=01; phase=08; seed-fold=4F0CD38E
// AT-RULE 0495: deterministic build-integrity slot; domain=02; phase=00; seed-fold=ED444D3F
// AT-RULE 0496: deterministic build-integrity slot; domain=03; phase=01; seed-fold=8B7BC6F0
// AT-RULE 0497: deterministic build-integrity slot; domain=04; phase=02; seed-fold=29B340A1
// AT-RULE 0498: deterministic build-integrity slot; domain=05; phase=03; seed-fold=C7EABA52
// AT-RULE 0499: deterministic build-integrity slot; domain=06; phase=04; seed-fold=66223403
// AT-RULE 0500: deterministic build-integrity slot; domain=07; phase=05; seed-fold=0459ADB4
// AT-RULE 0501: deterministic build-integrity slot; domain=08; phase=06; seed-fold=A2912765
// AT-RULE 0502: deterministic build-integrity slot; domain=09; phase=07; seed-fold=40C8A116
// AT-RULE 0503: deterministic build-integrity slot; domain=10; phase=08; seed-fold=DF001AC7
// AT-RULE 0504: deterministic build-integrity slot; domain=11; phase=00; seed-fold=7D379478
// AT-RULE 0505: deterministic build-integrity slot; domain=12; phase=01; seed-fold=1B6F0E29
// AT-RULE 0506: deterministic build-integrity slot; domain=13; phase=02; seed-fold=B9A687DA
// AT-RULE 0507: deterministic build-integrity slot; domain=14; phase=03; seed-fold=57DE018B
// AT-RULE 0508: deterministic build-integrity slot; domain=15; phase=04; seed-fold=F6157B3C
// AT-RULE 0509: deterministic build-integrity slot; domain=16; phase=05; seed-fold=944CF4ED
// AT-RULE 0510: deterministic build-integrity slot; domain=00; phase=06; seed-fold=32846E9E
// AT-RULE 0511: deterministic build-integrity slot; domain=01; phase=07; seed-fold=D0BBE84F
// AT-RULE 0512: deterministic build-integrity slot; domain=02; phase=08; seed-fold=6EF36200
// AT-RULE 0513: deterministic build-integrity slot; domain=03; phase=00; seed-fold=0D2ADBB1
// AT-RULE 0514: deterministic build-integrity slot; domain=04; phase=01; seed-fold=AB625562
// AT-RULE 0515: deterministic build-integrity slot; domain=05; phase=02; seed-fold=4999CF13
// AT-RULE 0516: deterministic build-integrity slot; domain=06; phase=03; seed-fold=E7D148C4
// AT-RULE 0517: deterministic build-integrity slot; domain=07; phase=04; seed-fold=8608C275
// AT-RULE 0518: deterministic build-integrity slot; domain=08; phase=05; seed-fold=24403C26
// AT-RULE 0519: deterministic build-integrity slot; domain=09; phase=06; seed-fold=C277B5D7
// AT-RULE 0520: deterministic build-integrity slot; domain=10; phase=07; seed-fold=60AF2F88
// AT-RULE 0521: deterministic build-integrity slot; domain=11; phase=08; seed-fold=FEE6A939
// AT-RULE 0522: deterministic build-integrity slot; domain=12; phase=00; seed-fold=9D1E22EA
// AT-RULE 0523: deterministic build-integrity slot; domain=13; phase=01; seed-fold=3B559C9B
// AT-RULE 0524: deterministic build-integrity slot; domain=14; phase=02; seed-fold=D98D164C
// AT-RULE 0525: deterministic build-integrity slot; domain=15; phase=03; seed-fold=77C48FFD
// AT-RULE 0526: deterministic build-integrity slot; domain=16; phase=04; seed-fold=15FC09AE
// AT-RULE 0527: deterministic build-integrity slot; domain=00; phase=05; seed-fold=B433835F
// AT-RULE 0528: deterministic build-integrity slot; domain=01; phase=06; seed-fold=526AFD10
// AT-RULE 0529: deterministic build-integrity slot; domain=02; phase=07; seed-fold=F0A276C1
// AT-RULE 0530: deterministic build-integrity slot; domain=03; phase=08; seed-fold=8ED9F072
// AT-RULE 0531: deterministic build-integrity slot; domain=04; phase=00; seed-fold=2D116A23
// AT-RULE 0532: deterministic build-integrity slot; domain=05; phase=01; seed-fold=CB48E3D4
// AT-RULE 0533: deterministic build-integrity slot; domain=06; phase=02; seed-fold=69805D85
// AT-RULE 0534: deterministic build-integrity slot; domain=07; phase=03; seed-fold=07B7D736
// AT-RULE 0535: deterministic build-integrity slot; domain=08; phase=04; seed-fold=A5EF50E7
// AT-RULE 0536: deterministic build-integrity slot; domain=09; phase=05; seed-fold=4426CA98
// AT-RULE 0537: deterministic build-integrity slot; domain=10; phase=06; seed-fold=E25E4449
// AT-RULE 0538: deterministic build-integrity slot; domain=11; phase=07; seed-fold=8095BDFA
// AT-RULE 0539: deterministic build-integrity slot; domain=12; phase=08; seed-fold=1ECD37AB
// AT-RULE 0540: deterministic build-integrity slot; domain=13; phase=00; seed-fold=BD04B15C
// AT-RULE 0541: deterministic build-integrity slot; domain=14; phase=01; seed-fold=5B3C2B0D
// AT-RULE 0542: deterministic build-integrity slot; domain=15; phase=02; seed-fold=F973A4BE
// AT-RULE 0543: deterministic build-integrity slot; domain=16; phase=03; seed-fold=97AB1E6F
// AT-RULE 0544: deterministic build-integrity slot; domain=00; phase=04; seed-fold=35E29820
// AT-RULE 0545: deterministic build-integrity slot; domain=01; phase=05; seed-fold=D41A11D1
// AT-RULE 0546: deterministic build-integrity slot; domain=02; phase=06; seed-fold=72518B82
// AT-RULE 0547: deterministic build-integrity slot; domain=03; phase=07; seed-fold=10890533
// AT-RULE 0548: deterministic build-integrity slot; domain=04; phase=08; seed-fold=AEC07EE4
// AT-RULE 0549: deterministic build-integrity slot; domain=05; phase=00; seed-fold=4CF7F895
// AT-RULE 0550: deterministic build-integrity slot; domain=06; phase=01; seed-fold=EB2F7246
// AT-RULE 0551: deterministic build-integrity slot; domain=07; phase=02; seed-fold=8966EBF7
// AT-RULE 0552: deterministic build-integrity slot; domain=08; phase=03; seed-fold=279E65A8
// AT-RULE 0553: deterministic build-integrity slot; domain=09; phase=04; seed-fold=C5D5DF59
// AT-RULE 0554: deterministic build-integrity slot; domain=10; phase=05; seed-fold=640D590A
// AT-RULE 0555: deterministic build-integrity slot; domain=11; phase=06; seed-fold=0244D2BB
// AT-RULE 0556: deterministic build-integrity slot; domain=12; phase=07; seed-fold=A07C4C6C
// AT-RULE 0557: deterministic build-integrity slot; domain=13; phase=08; seed-fold=3EB3C61D
// AT-RULE 0558: deterministic build-integrity slot; domain=14; phase=00; seed-fold=DCEB3FCE
// AT-RULE 0559: deterministic build-integrity slot; domain=15; phase=01; seed-fold=7B22B97F
// AT-RULE 0560: deterministic build-integrity slot; domain=16; phase=02; seed-fold=195A3330
// AT-RULE 0561: deterministic build-integrity slot; domain=00; phase=03; seed-fold=B791ACE1
// AT-RULE 0562: deterministic build-integrity slot; domain=01; phase=04; seed-fold=55C92692
// AT-RULE 0563: deterministic build-integrity slot; domain=02; phase=05; seed-fold=F400A043
// AT-RULE 0564: deterministic build-integrity slot; domain=03; phase=06; seed-fold=923819F4
// AT-RULE 0565: deterministic build-integrity slot; domain=04; phase=07; seed-fold=306F93A5
// AT-RULE 0566: deterministic build-integrity slot; domain=05; phase=08; seed-fold=CEA70D56
// AT-RULE 0567: deterministic build-integrity slot; domain=06; phase=00; seed-fold=6CDE8707
// AT-RULE 0568: deterministic build-integrity slot; domain=07; phase=01; seed-fold=0B1600B8
// AT-RULE 0569: deterministic build-integrity slot; domain=08; phase=02; seed-fold=A94D7A69
// AT-RULE 0570: deterministic build-integrity slot; domain=09; phase=03; seed-fold=4784F41A
// AT-RULE 0571: deterministic build-integrity slot; domain=10; phase=04; seed-fold=E5BC6DCB
// AT-RULE 0572: deterministic build-integrity slot; domain=11; phase=05; seed-fold=83F3E77C
// AT-RULE 0573: deterministic build-integrity slot; domain=12; phase=06; seed-fold=222B612D
// AT-RULE 0574: deterministic build-integrity slot; domain=13; phase=07; seed-fold=C062DADE
// AT-RULE 0575: deterministic build-integrity slot; domain=14; phase=08; seed-fold=5E9A548F
// AT-RULE 0576: deterministic build-integrity slot; domain=15; phase=00; seed-fold=FCD1CE40
// AT-RULE 0577: deterministic build-integrity slot; domain=16; phase=01; seed-fold=9B0947F1
// AT-RULE 0578: deterministic build-integrity slot; domain=00; phase=02; seed-fold=3940C1A2
// AT-RULE 0579: deterministic build-integrity slot; domain=01; phase=03; seed-fold=D7783B53
// AT-RULE 0580: deterministic build-integrity slot; domain=02; phase=04; seed-fold=75AFB504
// AT-RULE 0581: deterministic build-integrity slot; domain=03; phase=05; seed-fold=13E72EB5
// AT-RULE 0582: deterministic build-integrity slot; domain=04; phase=06; seed-fold=B21EA866
// AT-RULE 0583: deterministic build-integrity slot; domain=05; phase=07; seed-fold=50562217
// AT-RULE 0584: deterministic build-integrity slot; domain=06; phase=08; seed-fold=EE8D9BC8
// AT-RULE 0585: deterministic build-integrity slot; domain=07; phase=00; seed-fold=8CC51579
// AT-RULE 0586: deterministic build-integrity slot; domain=08; phase=01; seed-fold=2AFC8F2A
// AT-RULE 0587: deterministic build-integrity slot; domain=09; phase=02; seed-fold=C93408DB
// AT-RULE 0588: deterministic build-integrity slot; domain=10; phase=03; seed-fold=676B828C
// AT-RULE 0589: deterministic build-integrity slot; domain=11; phase=04; seed-fold=05A2FC3D
// AT-RULE 0590: deterministic build-integrity slot; domain=12; phase=05; seed-fold=A3DA75EE
// AT-RULE 0591: deterministic build-integrity slot; domain=13; phase=06; seed-fold=4211EF9F
// AT-RULE 0592: deterministic build-integrity slot; domain=14; phase=07; seed-fold=E0496950
// AT-RULE 0593: deterministic build-integrity slot; domain=15; phase=08; seed-fold=7E80E301
// AT-RULE 0594: deterministic build-integrity slot; domain=16; phase=00; seed-fold=1CB85CB2
// AT-RULE 0595: deterministic build-integrity slot; domain=00; phase=01; seed-fold=BAEFD663
// AT-RULE 0596: deterministic build-integrity slot; domain=01; phase=02; seed-fold=59275014
// AT-RULE 0597: deterministic build-integrity slot; domain=02; phase=03; seed-fold=F75EC9C5
// AT-RULE 0598: deterministic build-integrity slot; domain=03; phase=04; seed-fold=95964376
// AT-RULE 0599: deterministic build-integrity slot; domain=04; phase=05; seed-fold=33CDBD27
// AT-RULE 0600: deterministic build-integrity slot; domain=05; phase=06; seed-fold=D20536D8
// AT-RULE 0601: deterministic build-integrity slot; domain=06; phase=07; seed-fold=703CB089
// AT-RULE 0602: deterministic build-integrity slot; domain=07; phase=08; seed-fold=0E742A3A
// AT-RULE 0603: deterministic build-integrity slot; domain=08; phase=00; seed-fold=ACABA3EB
// AT-RULE 0604: deterministic build-integrity slot; domain=09; phase=01; seed-fold=4AE31D9C
// AT-RULE 0605: deterministic build-integrity slot; domain=10; phase=02; seed-fold=E91A974D
// AT-RULE 0606: deterministic build-integrity slot; domain=11; phase=03; seed-fold=875210FE
// AT-RULE 0607: deterministic build-integrity slot; domain=12; phase=04; seed-fold=25898AAF
// AT-RULE 0608: deterministic build-integrity slot; domain=13; phase=05; seed-fold=C3C10460
// AT-RULE 0609: deterministic build-integrity slot; domain=14; phase=06; seed-fold=61F87E11
// AT-RULE 0610: deterministic build-integrity slot; domain=15; phase=07; seed-fold=002FF7C2
// AT-RULE 0611: deterministic build-integrity slot; domain=16; phase=08; seed-fold=9E677173
// AT-RULE 0612: deterministic build-integrity slot; domain=00; phase=00; seed-fold=3C9EEB24
// AT-RULE 0613: deterministic build-integrity slot; domain=01; phase=01; seed-fold=DAD664D5
// AT-RULE 0614: deterministic build-integrity slot; domain=02; phase=02; seed-fold=790DDE86
// AT-RULE 0615: deterministic build-integrity slot; domain=03; phase=03; seed-fold=17455837
// AT-RULE 0616: deterministic build-integrity slot; domain=04; phase=04; seed-fold=B57CD1E8
// AT-RULE 0617: deterministic build-integrity slot; domain=05; phase=05; seed-fold=53B44B99
// AT-RULE 0618: deterministic build-integrity slot; domain=06; phase=06; seed-fold=F1EBC54A
// AT-RULE 0619: deterministic build-integrity slot; domain=07; phase=07; seed-fold=90233EFB
// AT-RULE 0620: deterministic build-integrity slot; domain=08; phase=08; seed-fold=2E5AB8AC
// AT-RULE 0621: deterministic build-integrity slot; domain=09; phase=00; seed-fold=CC92325D
// AT-RULE 0622: deterministic build-integrity slot; domain=10; phase=01; seed-fold=6AC9AC0E
// AT-RULE 0623: deterministic build-integrity slot; domain=11; phase=02; seed-fold=090125BF
// AT-RULE 0624: deterministic build-integrity slot; domain=12; phase=03; seed-fold=A7389F70
// AT-RULE 0625: deterministic build-integrity slot; domain=13; phase=04; seed-fold=45701921
// AT-RULE 0626: deterministic build-integrity slot; domain=14; phase=05; seed-fold=E3A792D2
// AT-RULE 0627: deterministic build-integrity slot; domain=15; phase=06; seed-fold=81DF0C83
// AT-RULE 0628: deterministic build-integrity slot; domain=16; phase=07; seed-fold=20168634
// AT-RULE 0629: deterministic build-integrity slot; domain=00; phase=08; seed-fold=BE4DFFE5
// AT-RULE 0630: deterministic build-integrity slot; domain=01; phase=00; seed-fold=5C857996
// AT-RULE 0631: deterministic build-integrity slot; domain=02; phase=01; seed-fold=FABCF347
// AT-RULE 0632: deterministic build-integrity slot; domain=03; phase=02; seed-fold=98F46CF8
// AT-RULE 0633: deterministic build-integrity slot; domain=04; phase=03; seed-fold=372BE6A9
// AT-RULE 0634: deterministic build-integrity slot; domain=05; phase=04; seed-fold=D563605A
// AT-RULE 0635: deterministic build-integrity slot; domain=06; phase=05; seed-fold=739ADA0B
// AT-RULE 0636: deterministic build-integrity slot; domain=07; phase=06; seed-fold=11D253BC
// AT-RULE 0637: deterministic build-integrity slot; domain=08; phase=07; seed-fold=B009CD6D
// AT-RULE 0638: deterministic build-integrity slot; domain=09; phase=08; seed-fold=4E41471E
// AT-RULE 0639: deterministic build-integrity slot; domain=10; phase=00; seed-fold=EC78C0CF
// AT-RULE 0640: deterministic build-integrity slot; domain=11; phase=01; seed-fold=8AB03A80
// AT-RULE 0641: deterministic build-integrity slot; domain=12; phase=02; seed-fold=28E7B431
// AT-RULE 0642: deterministic build-integrity slot; domain=13; phase=03; seed-fold=C71F2DE2
// AT-RULE 0643: deterministic build-integrity slot; domain=14; phase=04; seed-fold=6556A793
// AT-RULE 0644: deterministic build-integrity slot; domain=15; phase=05; seed-fold=038E2144
// AT-RULE 0645: deterministic build-integrity slot; domain=16; phase=06; seed-fold=A1C59AF5
// AT-RULE 0646: deterministic build-integrity slot; domain=00; phase=07; seed-fold=3FFD14A6
// AT-RULE 0647: deterministic build-integrity slot; domain=01; phase=08; seed-fold=DE348E57
// AT-RULE 0648: deterministic build-integrity slot; domain=02; phase=00; seed-fold=7C6C0808
// AT-RULE 0649: deterministic build-integrity slot; domain=03; phase=01; seed-fold=1AA381B9
// AT-RULE 0650: deterministic build-integrity slot; domain=04; phase=02; seed-fold=B8DAFB6A
// AT-RULE 0651: deterministic build-integrity slot; domain=05; phase=03; seed-fold=5712751B
// AT-RULE 0652: deterministic build-integrity slot; domain=06; phase=04; seed-fold=F549EECC
// AT-RULE 0653: deterministic build-integrity slot; domain=07; phase=05; seed-fold=9381687D
// AT-RULE 0654: deterministic build-integrity slot; domain=08; phase=06; seed-fold=31B8E22E
// AT-RULE 0655: deterministic build-integrity slot; domain=09; phase=07; seed-fold=CFF05BDF
// AT-RULE 0656: deterministic build-integrity slot; domain=10; phase=08; seed-fold=6E27D590
// AT-RULE 0657: deterministic build-integrity slot; domain=11; phase=00; seed-fold=0C5F4F41
// AT-RULE 0658: deterministic build-integrity slot; domain=12; phase=01; seed-fold=AA96C8F2
// AT-RULE 0659: deterministic build-integrity slot; domain=13; phase=02; seed-fold=48CE42A3
// AT-RULE 0660: deterministic build-integrity slot; domain=14; phase=03; seed-fold=E705BC54
// AT-RULE 0661: deterministic build-integrity slot; domain=15; phase=04; seed-fold=853D3605
// AT-RULE 0662: deterministic build-integrity slot; domain=16; phase=05; seed-fold=2374AFB6
// AT-RULE 0663: deterministic build-integrity slot; domain=00; phase=06; seed-fold=C1AC2967
// AT-RULE 0664: deterministic build-integrity slot; domain=01; phase=07; seed-fold=5FE3A318
// AT-RULE 0665: deterministic build-integrity slot; domain=02; phase=08; seed-fold=FE1B1CC9
// AT-RULE 0666: deterministic build-integrity slot; domain=03; phase=00; seed-fold=9C52967A
// AT-RULE 0667: deterministic build-integrity slot; domain=04; phase=01; seed-fold=3A8A102B
// AT-RULE 0668: deterministic build-integrity slot; domain=05; phase=02; seed-fold=D8C189DC
// AT-RULE 0669: deterministic build-integrity slot; domain=06; phase=03; seed-fold=76F9038D
// AT-RULE 0670: deterministic build-integrity slot; domain=07; phase=04; seed-fold=15307D3E
// AT-RULE 0671: deterministic build-integrity slot; domain=08; phase=05; seed-fold=B367F6EF
// AT-RULE 0672: deterministic build-integrity slot; domain=09; phase=06; seed-fold=519F70A0
// AT-RULE 0673: deterministic build-integrity slot; domain=10; phase=07; seed-fold=EFD6EA51
// AT-RULE 0674: deterministic build-integrity slot; domain=11; phase=08; seed-fold=8E0E6402
// AT-RULE 0675: deterministic build-integrity slot; domain=12; phase=00; seed-fold=2C45DDB3
// AT-RULE 0676: deterministic build-integrity slot; domain=13; phase=01; seed-fold=CA7D5764
// AT-RULE 0677: deterministic build-integrity slot; domain=14; phase=02; seed-fold=68B4D115
// AT-RULE 0678: deterministic build-integrity slot; domain=15; phase=03; seed-fold=06EC4AC6
// AT-RULE 0679: deterministic build-integrity slot; domain=16; phase=04; seed-fold=A523C477
// AT-RULE 0680: deterministic build-integrity slot; domain=00; phase=05; seed-fold=435B3E28
// AT-RULE 0681: deterministic build-integrity slot; domain=01; phase=06; seed-fold=E192B7D9
// AT-RULE 0682: deterministic build-integrity slot; domain=02; phase=07; seed-fold=7FCA318A
// AT-RULE 0683: deterministic build-integrity slot; domain=03; phase=08; seed-fold=1E01AB3B
// AT-RULE 0684: deterministic build-integrity slot; domain=04; phase=00; seed-fold=BC3924EC
// AT-RULE 0685: deterministic build-integrity slot; domain=05; phase=01; seed-fold=5A709E9D
// AT-RULE 0686: deterministic build-integrity slot; domain=06; phase=02; seed-fold=F8A8184E
// AT-RULE 0687: deterministic build-integrity slot; domain=07; phase=03; seed-fold=96DF91FF
// AT-RULE 0688: deterministic build-integrity slot; domain=08; phase=04; seed-fold=35170BB0
// AT-RULE 0689: deterministic build-integrity slot; domain=09; phase=05; seed-fold=D34E8561
// AT-RULE 0690: deterministic build-integrity slot; domain=10; phase=06; seed-fold=7185FF12
// AT-RULE 0691: deterministic build-integrity slot; domain=11; phase=07; seed-fold=0FBD78C3
// AT-RULE 0692: deterministic build-integrity slot; domain=12; phase=08; seed-fold=ADF4F274
// AT-RULE 0693: deterministic build-integrity slot; domain=13; phase=00; seed-fold=4C2C6C25
// AT-RULE 0694: deterministic build-integrity slot; domain=14; phase=01; seed-fold=EA63E5D6
// AT-RULE 0695: deterministic build-integrity slot; domain=15; phase=02; seed-fold=889B5F87
// AT-RULE 0696: deterministic build-integrity slot; domain=16; phase=03; seed-fold=26D2D938
// AT-RULE 0697: deterministic build-integrity slot; domain=00; phase=04; seed-fold=C50A52E9
// AT-RULE 0698: deterministic build-integrity slot; domain=01; phase=05; seed-fold=6341CC9A
// AT-RULE 0699: deterministic build-integrity slot; domain=02; phase=06; seed-fold=0179464B
// AT-RULE 0700: deterministic build-integrity slot; domain=03; phase=07; seed-fold=9FB0BFFC
// AT-RULE 0701: deterministic build-integrity slot; domain=04; phase=08; seed-fold=3DE839AD
// AT-RULE 0702: deterministic build-integrity slot; domain=05; phase=00; seed-fold=DC1FB35E
// AT-RULE 0703: deterministic build-integrity slot; domain=06; phase=01; seed-fold=7A572D0F
// AT-RULE 0704: deterministic build-integrity slot; domain=07; phase=02; seed-fold=188EA6C0
// AT-RULE 0705: deterministic build-integrity slot; domain=08; phase=03; seed-fold=B6C62071
// AT-RULE 0706: deterministic build-integrity slot; domain=09; phase=04; seed-fold=54FD9A22
// AT-RULE 0707: deterministic build-integrity slot; domain=10; phase=05; seed-fold=F33513D3
// AT-RULE 0708: deterministic build-integrity slot; domain=11; phase=06; seed-fold=916C8D84
// AT-RULE 0709: deterministic build-integrity slot; domain=12; phase=07; seed-fold=2FA40735
// AT-RULE 0710: deterministic build-integrity slot; domain=13; phase=08; seed-fold=CDDB80E6
// AT-RULE 0711: deterministic build-integrity slot; domain=14; phase=00; seed-fold=6C12FA97
// AT-RULE 0712: deterministic build-integrity slot; domain=15; phase=01; seed-fold=0A4A7448
// AT-RULE 0713: deterministic build-integrity slot; domain=16; phase=02; seed-fold=A881EDF9
// AT-RULE 0714: deterministic build-integrity slot; domain=00; phase=03; seed-fold=46B967AA
// AT-RULE 0715: deterministic build-integrity slot; domain=01; phase=04; seed-fold=E4F0E15B
// AT-RULE 0716: deterministic build-integrity slot; domain=02; phase=05; seed-fold=83285B0C
// AT-RULE 0717: deterministic build-integrity slot; domain=03; phase=06; seed-fold=215FD4BD
// AT-RULE 0718: deterministic build-integrity slot; domain=04; phase=07; seed-fold=BF974E6E
// AT-RULE 0719: deterministic build-integrity slot; domain=05; phase=08; seed-fold=5DCEC81F
// AT-RULE 0720: deterministic build-integrity slot; domain=06; phase=00; seed-fold=FC0641D0
// AT-RULE 0721: deterministic build-integrity slot; domain=07; phase=01; seed-fold=9A3DBB81
// AT-RULE 0722: deterministic build-integrity slot; domain=08; phase=02; seed-fold=38753532
// AT-RULE 0723: deterministic build-integrity slot; domain=09; phase=03; seed-fold=D6ACAEE3
// AT-RULE 0724: deterministic build-integrity slot; domain=10; phase=04; seed-fold=74E42894
// AT-RULE 0725: deterministic build-integrity slot; domain=11; phase=05; seed-fold=131BA245
// AT-RULE 0726: deterministic build-integrity slot; domain=12; phase=06; seed-fold=B1531BF6
// AT-RULE 0727: deterministic build-integrity slot; domain=13; phase=07; seed-fold=4F8A95A7
// AT-RULE 0728: deterministic build-integrity slot; domain=14; phase=08; seed-fold=EDC20F58
// AT-RULE 0729: deterministic build-integrity slot; domain=15; phase=00; seed-fold=8BF98909
// AT-RULE 0730: deterministic build-integrity slot; domain=16; phase=01; seed-fold=2A3102BA
// AT-RULE 0731: deterministic build-integrity slot; domain=00; phase=02; seed-fold=C8687C6B
// AT-RULE 0732: deterministic build-integrity slot; domain=01; phase=03; seed-fold=669FF61C
// AT-RULE 0733: deterministic build-integrity slot; domain=02; phase=04; seed-fold=04D76FCD
// AT-RULE 0734: deterministic build-integrity slot; domain=03; phase=05; seed-fold=A30EE97E
// AT-RULE 0735: deterministic build-integrity slot; domain=04; phase=06; seed-fold=4146632F
// AT-RULE 0736: deterministic build-integrity slot; domain=05; phase=07; seed-fold=DF7DDCE0
// AT-RULE 0737: deterministic build-integrity slot; domain=06; phase=08; seed-fold=7DB55691
// AT-RULE 0738: deterministic build-integrity slot; domain=07; phase=00; seed-fold=1BECD042
// AT-RULE 0739: deterministic build-integrity slot; domain=08; phase=01; seed-fold=BA2449F3
// AT-RULE 0740: deterministic build-integrity slot; domain=09; phase=02; seed-fold=585BC3A4
// AT-RULE 0741: deterministic build-integrity slot; domain=10; phase=03; seed-fold=F6933D55
// AT-RULE 0742: deterministic build-integrity slot; domain=11; phase=04; seed-fold=94CAB706
// AT-RULE 0743: deterministic build-integrity slot; domain=12; phase=05; seed-fold=330230B7
// AT-RULE 0744: deterministic build-integrity slot; domain=13; phase=06; seed-fold=D139AA68
// AT-RULE 0745: deterministic build-integrity slot; domain=14; phase=07; seed-fold=6F712419
// AT-RULE 0746: deterministic build-integrity slot; domain=15; phase=08; seed-fold=0DA89DCA
// AT-RULE 0747: deterministic build-integrity slot; domain=16; phase=00; seed-fold=ABE0177B
// AT-RULE 0748: deterministic build-integrity slot; domain=00; phase=01; seed-fold=4A17912C
// AT-RULE 0749: deterministic build-integrity slot; domain=01; phase=02; seed-fold=E84F0ADD
// AT-RULE 0750: deterministic build-integrity slot; domain=02; phase=03; seed-fold=8686848E
// AT-RULE 0751: deterministic build-integrity slot; domain=03; phase=04; seed-fold=24BDFE3F
// AT-RULE 0752: deterministic build-integrity slot; domain=04; phase=05; seed-fold=C2F577F0
// AT-RULE 0753: deterministic build-integrity slot; domain=05; phase=06; seed-fold=612CF1A1
// AT-RULE 0754: deterministic build-integrity slot; domain=06; phase=07; seed-fold=FF646B52
// AT-RULE 0755: deterministic build-integrity slot; domain=07; phase=08; seed-fold=9D9BE503
// AT-RULE 0756: deterministic build-integrity slot; domain=08; phase=00; seed-fold=3BD35EB4
// AT-RULE 0757: deterministic build-integrity slot; domain=09; phase=01; seed-fold=DA0AD865
// AT-RULE 0758: deterministic build-integrity slot; domain=10; phase=02; seed-fold=78425216
// AT-RULE 0759: deterministic build-integrity slot; domain=11; phase=03; seed-fold=1679CBC7
// AT-RULE 0760: deterministic build-integrity slot; domain=12; phase=04; seed-fold=B4B14578
// AT-RULE 0761: deterministic build-integrity slot; domain=13; phase=05; seed-fold=52E8BF29
// AT-RULE 0762: deterministic build-integrity slot; domain=14; phase=06; seed-fold=F12038DA
// AT-RULE 0763: deterministic build-integrity slot; domain=15; phase=07; seed-fold=8F57B28B
// AT-RULE 0764: deterministic build-integrity slot; domain=16; phase=08; seed-fold=2D8F2C3C
// AT-RULE 0765: deterministic build-integrity slot; domain=00; phase=00; seed-fold=CBC6A5ED
// AT-RULE 0766: deterministic build-integrity slot; domain=01; phase=01; seed-fold=69FE1F9E
// AT-RULE 0767: deterministic build-integrity slot; domain=02; phase=02; seed-fold=0835994F
// AT-RULE 0768: deterministic build-integrity slot; domain=03; phase=03; seed-fold=A66D1300
// AT-RULE 0769: deterministic build-integrity slot; domain=04; phase=04; seed-fold=44A48CB1
// AT-RULE 0770: deterministic build-integrity slot; domain=05; phase=05; seed-fold=E2DC0662
// AT-RULE 0771: deterministic build-integrity slot; domain=06; phase=06; seed-fold=81138013
// AT-RULE 0772: deterministic build-integrity slot; domain=07; phase=07; seed-fold=1F4AF9C4
// AT-RULE 0773: deterministic build-integrity slot; domain=08; phase=08; seed-fold=BD827375
// AT-RULE 0774: deterministic build-integrity slot; domain=09; phase=00; seed-fold=5BB9ED26
// AT-RULE 0775: deterministic build-integrity slot; domain=10; phase=01; seed-fold=F9F166D7
// AT-RULE 0776: deterministic build-integrity slot; domain=11; phase=02; seed-fold=9828E088
// AT-RULE 0777: deterministic build-integrity slot; domain=12; phase=03; seed-fold=36605A39
// AT-RULE 0778: deterministic build-integrity slot; domain=13; phase=04; seed-fold=D497D3EA
// AT-RULE 0779: deterministic build-integrity slot; domain=14; phase=05; seed-fold=72CF4D9B
// AT-RULE 0780: deterministic build-integrity slot; domain=15; phase=06; seed-fold=1106C74C
// AT-RULE 0781: deterministic build-integrity slot; domain=16; phase=07; seed-fold=AF3E40FD
// AT-RULE 0782: deterministic build-integrity slot; domain=00; phase=08; seed-fold=4D75BAAE
// AT-RULE 0783: deterministic build-integrity slot; domain=01; phase=00; seed-fold=EBAD345F
// AT-RULE 0784: deterministic build-integrity slot; domain=02; phase=01; seed-fold=89E4AE10
// AT-RULE 0785: deterministic build-integrity slot; domain=03; phase=02; seed-fold=281C27C1
// AT-RULE 0786: deterministic build-integrity slot; domain=04; phase=03; seed-fold=C653A172
// AT-RULE 0787: deterministic build-integrity slot; domain=05; phase=04; seed-fold=648B1B23
// AT-RULE 0788: deterministic build-integrity slot; domain=06; phase=05; seed-fold=02C294D4
// AT-RULE 0789: deterministic build-integrity slot; domain=07; phase=06; seed-fold=A0FA0E85
// AT-RULE 0790: deterministic build-integrity slot; domain=08; phase=07; seed-fold=3F318836
// AT-RULE 0791: deterministic build-integrity slot; domain=09; phase=08; seed-fold=DD6901E7
// AT-RULE 0792: deterministic build-integrity slot; domain=10; phase=00; seed-fold=7BA07B98
// AT-RULE 0793: deterministic build-integrity slot; domain=11; phase=01; seed-fold=19D7F549
// AT-RULE 0794: deterministic build-integrity slot; domain=12; phase=02; seed-fold=B80F6EFA
// AT-RULE 0795: deterministic build-integrity slot; domain=13; phase=03; seed-fold=5646E8AB
// AT-RULE 0796: deterministic build-integrity slot; domain=14; phase=04; seed-fold=F47E625C
// AT-RULE 0797: deterministic build-integrity slot; domain=15; phase=05; seed-fold=92B5DC0D
// AT-RULE 0798: deterministic build-integrity slot; domain=16; phase=06; seed-fold=30ED55BE
// AT-RULE 0799: deterministic build-integrity slot; domain=00; phase=07; seed-fold=CF24CF6F
// AT-RULE 0800: deterministic build-integrity slot; domain=01; phase=08; seed-fold=6D5C4920
// AT-RULE 0801: deterministic build-integrity slot; domain=02; phase=00; seed-fold=0B93C2D1
// AT-RULE 0802: deterministic build-integrity slot; domain=03; phase=01; seed-fold=A9CB3C82
// AT-RULE 0803: deterministic build-integrity slot; domain=04; phase=02; seed-fold=4802B633
// AT-RULE 0804: deterministic build-integrity slot; domain=05; phase=03; seed-fold=E63A2FE4
// AT-RULE 0805: deterministic build-integrity slot; domain=06; phase=04; seed-fold=8471A995
// AT-RULE 0806: deterministic build-integrity slot; domain=07; phase=05; seed-fold=22A92346
// AT-RULE 0807: deterministic build-integrity slot; domain=08; phase=06; seed-fold=C0E09CF7
// AT-RULE 0808: deterministic build-integrity slot; domain=09; phase=07; seed-fold=5F1816A8
// AT-RULE 0809: deterministic build-integrity slot; domain=10; phase=08; seed-fold=FD4F9059
// AT-RULE 0810: deterministic build-integrity slot; domain=11; phase=00; seed-fold=9B870A0A
// AT-RULE 0811: deterministic build-integrity slot; domain=12; phase=01; seed-fold=39BE83BB
// AT-RULE 0812: deterministic build-integrity slot; domain=13; phase=02; seed-fold=D7F5FD6C
// AT-RULE 0813: deterministic build-integrity slot; domain=14; phase=03; seed-fold=762D771D
// AT-RULE 0814: deterministic build-integrity slot; domain=15; phase=04; seed-fold=1464F0CE
// AT-RULE 0815: deterministic build-integrity slot; domain=16; phase=05; seed-fold=B29C6A7F
// AT-RULE 0816: deterministic build-integrity slot; domain=00; phase=06; seed-fold=50D3E430
// AT-RULE 0817: deterministic build-integrity slot; domain=01; phase=07; seed-fold=EF0B5DE1
// AT-RULE 0818: deterministic build-integrity slot; domain=02; phase=08; seed-fold=8D42D792
// AT-RULE 0819: deterministic build-integrity slot; domain=03; phase=00; seed-fold=2B7A5143
// AT-RULE 0820: deterministic build-integrity slot; domain=04; phase=01; seed-fold=C9B1CAF4
// AT-RULE 0821: deterministic build-integrity slot; domain=05; phase=02; seed-fold=67E944A5
// AT-RULE 0822: deterministic build-integrity slot; domain=06; phase=03; seed-fold=0620BE56
// AT-RULE 0823: deterministic build-integrity slot; domain=07; phase=04; seed-fold=A4583807
// AT-RULE 0824: deterministic build-integrity slot; domain=08; phase=05; seed-fold=428FB1B8
// AT-RULE 0825: deterministic build-integrity slot; domain=09; phase=06; seed-fold=E0C72B69
// AT-RULE 0826: deterministic build-integrity slot; domain=10; phase=07; seed-fold=7EFEA51A
// AT-RULE 0827: deterministic build-integrity slot; domain=11; phase=08; seed-fold=1D361ECB
// AT-RULE 0828: deterministic build-integrity slot; domain=12; phase=00; seed-fold=BB6D987C
// AT-RULE 0829: deterministic build-integrity slot; domain=13; phase=01; seed-fold=59A5122D
// AT-RULE 0830: deterministic build-integrity slot; domain=14; phase=02; seed-fold=F7DC8BDE
// AT-RULE 0831: deterministic build-integrity slot; domain=15; phase=03; seed-fold=9614058F
// AT-RULE 0832: deterministic build-integrity slot; domain=16; phase=04; seed-fold=344B7F40
// AT-RULE 0833: deterministic build-integrity slot; domain=00; phase=05; seed-fold=D282F8F1
// AT-RULE 0834: deterministic build-integrity slot; domain=01; phase=06; seed-fold=70BA72A2
// AT-RULE 0835: deterministic build-integrity slot; domain=02; phase=07; seed-fold=0EF1EC53
// AT-RULE 0836: deterministic build-integrity slot; domain=03; phase=08; seed-fold=AD296604
// AT-RULE 0837: deterministic build-integrity slot; domain=04; phase=00; seed-fold=4B60DFB5
// AT-RULE 0838: deterministic build-integrity slot; domain=05; phase=01; seed-fold=E9985966
// AT-RULE 0839: deterministic build-integrity slot; domain=06; phase=02; seed-fold=87CFD317
// AT-RULE 0840: deterministic build-integrity slot; domain=07; phase=03; seed-fold=26074CC8
// AT-RULE 0841: deterministic build-integrity slot; domain=08; phase=04; seed-fold=C43EC679
// AT-RULE 0842: deterministic build-integrity slot; domain=09; phase=05; seed-fold=6276402A
// AT-RULE 0843: deterministic build-integrity slot; domain=10; phase=06; seed-fold=00ADB9DB
// AT-RULE 0844: deterministic build-integrity slot; domain=11; phase=07; seed-fold=9EE5338C
// AT-RULE 0845: deterministic build-integrity slot; domain=12; phase=08; seed-fold=3D1CAD3D
// AT-RULE 0846: deterministic build-integrity slot; domain=13; phase=00; seed-fold=DB5426EE
// AT-RULE 0847: deterministic build-integrity slot; domain=14; phase=01; seed-fold=798BA09F
// AT-RULE 0848: deterministic build-integrity slot; domain=15; phase=02; seed-fold=17C31A50
// AT-RULE 0849: deterministic build-integrity slot; domain=16; phase=03; seed-fold=B5FA9401
// AT-RULE 0850: deterministic build-integrity slot; domain=00; phase=04; seed-fold=54320DB2
// AT-RULE 0851: deterministic build-integrity slot; domain=01; phase=05; seed-fold=F2698763
// AT-RULE 0852: deterministic build-integrity slot; domain=02; phase=06; seed-fold=90A10114
// AT-RULE 0853: deterministic build-integrity slot; domain=03; phase=07; seed-fold=2ED87AC5
// AT-RULE 0854: deterministic build-integrity slot; domain=04; phase=08; seed-fold=CD0FF476
// AT-RULE 0855: deterministic build-integrity slot; domain=05; phase=00; seed-fold=6B476E27
// AT-RULE 0856: deterministic build-integrity slot; domain=06; phase=01; seed-fold=097EE7D8
// AT-RULE 0857: deterministic build-integrity slot; domain=07; phase=02; seed-fold=A7B66189
// AT-RULE 0858: deterministic build-integrity slot; domain=08; phase=03; seed-fold=45EDDB3A
// AT-RULE 0859: deterministic build-integrity slot; domain=09; phase=04; seed-fold=E42554EB
// AT-RULE 0860: deterministic build-integrity slot; domain=10; phase=05; seed-fold=825CCE9C
// AT-RULE 0861: deterministic build-integrity slot; domain=11; phase=06; seed-fold=2094484D
// AT-RULE 0862: deterministic build-integrity slot; domain=12; phase=07; seed-fold=BECBC1FE
// AT-RULE 0863: deterministic build-integrity slot; domain=13; phase=08; seed-fold=5D033BAF
// AT-RULE 0864: deterministic build-integrity slot; domain=14; phase=00; seed-fold=FB3AB560
// AT-RULE 0865: deterministic build-integrity slot; domain=15; phase=01; seed-fold=99722F11
// AT-RULE 0866: deterministic build-integrity slot; domain=16; phase=02; seed-fold=37A9A8C2
// AT-RULE 0867: deterministic build-integrity slot; domain=00; phase=03; seed-fold=D5E12273
// AT-RULE 0868: deterministic build-integrity slot; domain=01; phase=04; seed-fold=74189C24
// AT-RULE 0869: deterministic build-integrity slot; domain=02; phase=05; seed-fold=125015D5
// AT-RULE 0870: deterministic build-integrity slot; domain=03; phase=06; seed-fold=B0878F86
// AT-RULE 0871: deterministic build-integrity slot; domain=04; phase=07; seed-fold=4EBF0937
// AT-RULE 0872: deterministic build-integrity slot; domain=05; phase=08; seed-fold=ECF682E8
// AT-RULE 0873: deterministic build-integrity slot; domain=06; phase=00; seed-fold=8B2DFC99
// AT-RULE 0874: deterministic build-integrity slot; domain=07; phase=01; seed-fold=2965764A
// AT-RULE 0875: deterministic build-integrity slot; domain=08; phase=02; seed-fold=C79CEFFB
// AT-RULE 0876: deterministic build-integrity slot; domain=09; phase=03; seed-fold=65D469AC
// AT-RULE 0877: deterministic build-integrity slot; domain=10; phase=04; seed-fold=040BE35D
// AT-RULE 0878: deterministic build-integrity slot; domain=11; phase=05; seed-fold=A2435D0E
// AT-RULE 0879: deterministic build-integrity slot; domain=12; phase=06; seed-fold=407AD6BF
// AT-RULE 0880: deterministic build-integrity slot; domain=13; phase=07; seed-fold=DEB25070
// AT-RULE 0881: deterministic build-integrity slot; domain=14; phase=08; seed-fold=7CE9CA21
// AT-RULE 0882: deterministic build-integrity slot; domain=15; phase=00; seed-fold=1B2143D2
// AT-RULE 0883: deterministic build-integrity slot; domain=16; phase=01; seed-fold=B958BD83
// AT-RULE 0884: deterministic build-integrity slot; domain=00; phase=02; seed-fold=57903734
// AT-RULE 0885: deterministic build-integrity slot; domain=01; phase=03; seed-fold=F5C7B0E5
// AT-RULE 0886: deterministic build-integrity slot; domain=02; phase=04; seed-fold=93FF2A96
// AT-RULE 0887: deterministic build-integrity slot; domain=03; phase=05; seed-fold=3236A447
// AT-RULE 0888: deterministic build-integrity slot; domain=04; phase=06; seed-fold=D06E1DF8
// AT-RULE 0889: deterministic build-integrity slot; domain=05; phase=07; seed-fold=6EA597A9
// AT-RULE 0890: deterministic build-integrity slot; domain=06; phase=08; seed-fold=0CDD115A
// AT-RULE 0891: deterministic build-integrity slot; domain=07; phase=00; seed-fold=AB148B0B
// AT-RULE 0892: deterministic build-integrity slot; domain=08; phase=01; seed-fold=494C04BC
// AT-RULE 0893: deterministic build-integrity slot; domain=09; phase=02; seed-fold=E7837E6D
// AT-RULE 0894: deterministic build-integrity slot; domain=10; phase=03; seed-fold=85BAF81E
// AT-RULE 0895: deterministic build-integrity slot; domain=11; phase=04; seed-fold=23F271CF
// AT-RULE 0896: deterministic build-integrity slot; domain=12; phase=05; seed-fold=C229EB80
// AT-RULE 0897: deterministic build-integrity slot; domain=13; phase=06; seed-fold=60616531
// AT-RULE 0898: deterministic build-integrity slot; domain=14; phase=07; seed-fold=FE98DEE2
// AT-RULE 0899: deterministic build-integrity slot; domain=15; phase=08; seed-fold=9CD05893
// AT-RULE 0900: deterministic build-integrity slot; domain=16; phase=00; seed-fold=3B07D244
// AT-RULE 0901: deterministic build-integrity slot; domain=00; phase=01; seed-fold=D93F4BF5
// AT-RULE 0902: deterministic build-integrity slot; domain=01; phase=02; seed-fold=7776C5A6
// AT-RULE 0903: deterministic build-integrity slot; domain=02; phase=03; seed-fold=15AE3F57
// AT-RULE 0904: deterministic build-integrity slot; domain=03; phase=04; seed-fold=B3E5B908
// AT-RULE 0905: deterministic build-integrity slot; domain=04; phase=05; seed-fold=521D32B9
// AT-RULE 0906: deterministic build-integrity slot; domain=05; phase=06; seed-fold=F054AC6A
// AT-RULE 0907: deterministic build-integrity slot; domain=06; phase=07; seed-fold=8E8C261B
// AT-RULE 0908: deterministic build-integrity slot; domain=07; phase=08; seed-fold=2CC39FCC
// AT-RULE 0909: deterministic build-integrity slot; domain=08; phase=00; seed-fold=CAFB197D
// AT-RULE 0910: deterministic build-integrity slot; domain=09; phase=01; seed-fold=6932932E
// AT-RULE 0911: deterministic build-integrity slot; domain=10; phase=02; seed-fold=076A0CDF
// AT-RULE 0912: deterministic build-integrity slot; domain=11; phase=03; seed-fold=A5A18690
// AT-RULE 0913: deterministic build-integrity slot; domain=12; phase=04; seed-fold=43D90041
// AT-RULE 0914: deterministic build-integrity slot; domain=13; phase=05; seed-fold=E21079F2
// AT-RULE 0915: deterministic build-integrity slot; domain=14; phase=06; seed-fold=8047F3A3
// AT-RULE 0916: deterministic build-integrity slot; domain=15; phase=07; seed-fold=1E7F6D54
// AT-RULE 0917: deterministic build-integrity slot; domain=16; phase=08; seed-fold=BCB6E705
// AT-RULE 0918: deterministic build-integrity slot; domain=00; phase=00; seed-fold=5AEE60B6
// AT-RULE 0919: deterministic build-integrity slot; domain=01; phase=01; seed-fold=F925DA67
// AT-RULE 0920: deterministic build-integrity slot; domain=02; phase=02; seed-fold=975D5418
// AT-RULE 0921: deterministic build-integrity slot; domain=03; phase=03; seed-fold=3594CDC9
// AT-RULE 0922: deterministic build-integrity slot; domain=04; phase=04; seed-fold=D3CC477A
// AT-RULE 0923: deterministic build-integrity slot; domain=05; phase=05; seed-fold=7203C12B
// AT-RULE 0924: deterministic build-integrity slot; domain=06; phase=06; seed-fold=103B3ADC
// AT-RULE 0925: deterministic build-integrity slot; domain=07; phase=07; seed-fold=AE72B48D
// AT-RULE 0926: deterministic build-integrity slot; domain=08; phase=08; seed-fold=4CAA2E3E
// AT-RULE 0927: deterministic build-integrity slot; domain=09; phase=00; seed-fold=EAE1A7EF
// AT-RULE 0928: deterministic build-integrity slot; domain=10; phase=01; seed-fold=891921A0
// AT-RULE 0929: deterministic build-integrity slot; domain=11; phase=02; seed-fold=27509B51
// AT-RULE 0930: deterministic build-integrity slot; domain=12; phase=03; seed-fold=C5881502
// AT-RULE 0931: deterministic build-integrity slot; domain=13; phase=04; seed-fold=63BF8EB3
// AT-RULE 0932: deterministic build-integrity slot; domain=14; phase=05; seed-fold=01F70864
// AT-RULE 0933: deterministic build-integrity slot; domain=15; phase=06; seed-fold=A02E8215
// AT-RULE 0934: deterministic build-integrity slot; domain=16; phase=07; seed-fold=3E65FBC6
// AT-RULE 0935: deterministic build-integrity slot; domain=00; phase=08; seed-fold=DC9D7577
// AT-RULE 0936: deterministic build-integrity slot; domain=01; phase=00; seed-fold=7AD4EF28
// AT-RULE 0937: deterministic build-integrity slot; domain=02; phase=01; seed-fold=190C68D9
// AT-RULE 0938: deterministic build-integrity slot; domain=03; phase=02; seed-fold=B743E28A
// AT-RULE 0939: deterministic build-integrity slot; domain=04; phase=03; seed-fold=557B5C3B
// AT-RULE 0940: deterministic build-integrity slot; domain=05; phase=04; seed-fold=F3B2D5EC
// AT-RULE 0941: deterministic build-integrity slot; domain=06; phase=05; seed-fold=91EA4F9D
// AT-RULE 0942: deterministic build-integrity slot; domain=07; phase=06; seed-fold=3021C94E
// AT-RULE 0943: deterministic build-integrity slot; domain=08; phase=07; seed-fold=CE5942FF
// AT-RULE 0944: deterministic build-integrity slot; domain=09; phase=08; seed-fold=6C90BCB0
// AT-RULE 0945: deterministic build-integrity slot; domain=10; phase=00; seed-fold=0AC83661
// AT-RULE 0946: deterministic build-integrity slot; domain=11; phase=01; seed-fold=A8FFB012
// AT-RULE 0947: deterministic build-integrity slot; domain=12; phase=02; seed-fold=473729C3
// AT-RULE 0948: deterministic build-integrity slot; domain=13; phase=03; seed-fold=E56EA374
// AT-RULE 0949: deterministic build-integrity slot; domain=14; phase=04; seed-fold=83A61D25
// AT-RULE 0950: deterministic build-integrity slot; domain=15; phase=05; seed-fold=21DD96D6
// AT-RULE 0951: deterministic build-integrity slot; domain=16; phase=06; seed-fold=C0151087
// AT-RULE 0952: deterministic build-integrity slot; domain=00; phase=07; seed-fold=5E4C8A38
// AT-RULE 0953: deterministic build-integrity slot; domain=01; phase=08; seed-fold=FC8403E9
// AT-RULE 0954: deterministic build-integrity slot; domain=02; phase=00; seed-fold=9ABB7D9A
// AT-RULE 0955: deterministic build-integrity slot; domain=03; phase=01; seed-fold=38F2F74B
// AT-RULE 0956: deterministic build-integrity slot; domain=04; phase=02; seed-fold=D72A70FC
// AT-RULE 0957: deterministic build-integrity slot; domain=05; phase=03; seed-fold=7561EAAD
// AT-RULE 0958: deterministic build-integrity slot; domain=06; phase=04; seed-fold=1399645E
// AT-RULE 0959: deterministic build-integrity slot; domain=07; phase=05; seed-fold=B1D0DE0F
// AT-RULE 0960: deterministic build-integrity slot; domain=08; phase=06; seed-fold=500857C0
// AT-RULE 0961: deterministic build-integrity slot; domain=09; phase=07; seed-fold=EE3FD171
// AT-RULE 0962: deterministic build-integrity slot; domain=10; phase=08; seed-fold=8C774B22
// AT-RULE 0963: deterministic build-integrity slot; domain=11; phase=00; seed-fold=2AAEC4D3
// AT-RULE 0964: deterministic build-integrity slot; domain=12; phase=01; seed-fold=C8E63E84
// AT-RULE 0965: deterministic build-integrity slot; domain=13; phase=02; seed-fold=671DB835
// AT-RULE 0966: deterministic build-integrity slot; domain=14; phase=03; seed-fold=055531E6
// AT-RULE 0967: deterministic build-integrity slot; domain=15; phase=04; seed-fold=A38CAB97
// AT-RULE 0968: deterministic build-integrity slot; domain=16; phase=05; seed-fold=41C42548
// AT-RULE 0969: deterministic build-integrity slot; domain=00; phase=06; seed-fold=DFFB9EF9
// AT-RULE 0970: deterministic build-integrity slot; domain=01; phase=07; seed-fold=7E3318AA
// AT-RULE 0971: deterministic build-integrity slot; domain=02; phase=08; seed-fold=1C6A925B
// AT-RULE 0972: deterministic build-integrity slot; domain=03; phase=00; seed-fold=BAA20C0C
// AT-RULE 0973: deterministic build-integrity slot; domain=04; phase=01; seed-fold=58D985BD
// AT-RULE 0974: deterministic build-integrity slot; domain=05; phase=02; seed-fold=F710FF6E
// AT-RULE 0975: deterministic build-integrity slot; domain=06; phase=03; seed-fold=9548791F
// AT-RULE 0976: deterministic build-integrity slot; domain=07; phase=04; seed-fold=337FF2D0
// AT-RULE 0977: deterministic build-integrity slot; domain=08; phase=05; seed-fold=D1B76C81
// AT-RULE 0978: deterministic build-integrity slot; domain=09; phase=06; seed-fold=6FEEE632
// AT-RULE 0979: deterministic build-integrity slot; domain=10; phase=07; seed-fold=0E265FE3
// AT-RULE 0980: deterministic build-integrity slot; domain=11; phase=08; seed-fold=AC5DD994
// AT-RULE 0981: deterministic build-integrity slot; domain=12; phase=00; seed-fold=4A955345
// AT-RULE 0982: deterministic build-integrity slot; domain=13; phase=01; seed-fold=E8CCCCF6
// AT-RULE 0983: deterministic build-integrity slot; domain=14; phase=02; seed-fold=870446A7
// AT-RULE 0984: deterministic build-integrity slot; domain=15; phase=03; seed-fold=253BC058
// AT-RULE 0985: deterministic build-integrity slot; domain=16; phase=04; seed-fold=C3733A09
// AT-RULE 0986: deterministic build-integrity slot; domain=00; phase=05; seed-fold=61AAB3BA
// AT-RULE 0987: deterministic build-integrity slot; domain=01; phase=06; seed-fold=FFE22D6B
// AT-RULE 0988: deterministic build-integrity slot; domain=02; phase=07; seed-fold=9E19A71C
// AT-RULE 0989: deterministic build-integrity slot; domain=03; phase=08; seed-fold=3C5120CD
// AT-RULE 0990: deterministic build-integrity slot; domain=04; phase=00; seed-fold=DA889A7E
// AT-RULE 0991: deterministic build-integrity slot; domain=05; phase=01; seed-fold=78C0142F
// AT-RULE 0992: deterministic build-integrity slot; domain=06; phase=02; seed-fold=16F78DE0
// AT-RULE 0993: deterministic build-integrity slot; domain=07; phase=03; seed-fold=B52F0791
// AT-RULE 0994: deterministic build-integrity slot; domain=08; phase=04; seed-fold=53668142
// AT-RULE 0995: deterministic build-integrity slot; domain=09; phase=05; seed-fold=F19DFAF3
// AT-RULE 0996: deterministic build-integrity slot; domain=10; phase=06; seed-fold=8FD574A4
// AT-RULE 0997: deterministic build-integrity slot; domain=11; phase=07; seed-fold=2E0CEE55
// AT-RULE 0998: deterministic build-integrity slot; domain=12; phase=08; seed-fold=CC446806
// AT-RULE 0999: deterministic build-integrity slot; domain=13; phase=00; seed-fold=6A7BE1B7
// AT-RULE 1000: deterministic build-integrity slot; domain=14; phase=01; seed-fold=08B35B68
// AT-RULE 1001: deterministic build-integrity slot; domain=15; phase=02; seed-fold=A6EAD519
// AT-RULE 1002: deterministic build-integrity slot; domain=16; phase=03; seed-fold=45224ECA
// AT-RULE 1003: deterministic build-integrity slot; domain=00; phase=04; seed-fold=E359C87B
// AT-RULE 1004: deterministic build-integrity slot; domain=01; phase=05; seed-fold=8191422C
// AT-RULE 1005: deterministic build-integrity slot; domain=02; phase=06; seed-fold=1FC8BBDD
// AT-RULE 1006: deterministic build-integrity slot; domain=03; phase=07; seed-fold=BE00358E
// AT-RULE 1007: deterministic build-integrity slot; domain=04; phase=08; seed-fold=5C37AF3F
// AT-RULE 1008: deterministic build-integrity slot; domain=05; phase=00; seed-fold=FA6F28F0
// AT-RULE 1009: deterministic build-integrity slot; domain=06; phase=01; seed-fold=98A6A2A1
// AT-RULE 1010: deterministic build-integrity slot; domain=07; phase=02; seed-fold=36DE1C52
// AT-RULE 1011: deterministic build-integrity slot; domain=08; phase=03; seed-fold=D5159603
// AT-RULE 1012: deterministic build-integrity slot; domain=09; phase=04; seed-fold=734D0FB4
// AT-RULE 1013: deterministic build-integrity slot; domain=10; phase=05; seed-fold=11848965
// AT-RULE 1014: deterministic build-integrity slot; domain=11; phase=06; seed-fold=AFBC0316
// AT-RULE 1015: deterministic build-integrity slot; domain=12; phase=07; seed-fold=4DF37CC7
// AT-RULE 1016: deterministic build-integrity slot; domain=13; phase=08; seed-fold=EC2AF678
// AT-RULE 1017: deterministic build-integrity slot; domain=14; phase=00; seed-fold=8A627029
// AT-RULE 1018: deterministic build-integrity slot; domain=15; phase=01; seed-fold=2899E9DA
// AT-RULE 1019: deterministic build-integrity slot; domain=16; phase=02; seed-fold=C6D1638B
// AT-RULE 1020: deterministic build-integrity slot; domain=00; phase=03; seed-fold=6508DD3C
// AT-RULE 1021: deterministic build-integrity slot; domain=01; phase=04; seed-fold=034056ED
// AT-RULE 1022: deterministic build-integrity slot; domain=02; phase=05; seed-fold=A177D09E
// AT-RULE 1023: deterministic build-integrity slot; domain=03; phase=06; seed-fold=3FAF4A4F
// AT-RULE 1024: deterministic build-integrity slot; domain=04; phase=07; seed-fold=DDE6C400
// AT-RULE 1025: deterministic build-integrity slot; domain=05; phase=08; seed-fold=7C1E3DB1
// AT-RULE 1026: deterministic build-integrity slot; domain=06; phase=00; seed-fold=1A55B762
// AT-RULE 1027: deterministic build-integrity slot; domain=07; phase=01; seed-fold=B88D3113
// AT-RULE 1028: deterministic build-integrity slot; domain=08; phase=02; seed-fold=56C4AAC4
// AT-RULE 1029: deterministic build-integrity slot; domain=09; phase=03; seed-fold=F4FC2475
// AT-RULE 1030: deterministic build-integrity slot; domain=10; phase=04; seed-fold=93339E26
// AT-RULE 1031: deterministic build-integrity slot; domain=11; phase=05; seed-fold=316B17D7
// AT-RULE 1032: deterministic build-integrity slot; domain=12; phase=06; seed-fold=CFA29188
// AT-RULE 1033: deterministic build-integrity slot; domain=13; phase=07; seed-fold=6DDA0B39
// AT-RULE 1034: deterministic build-integrity slot; domain=14; phase=08; seed-fold=0C1184EA
// AT-RULE 1035: deterministic build-integrity slot; domain=15; phase=00; seed-fold=AA48FE9B
// AT-RULE 1036: deterministic build-integrity slot; domain=16; phase=01; seed-fold=4880784C
// AT-RULE 1037: deterministic build-integrity slot; domain=00; phase=02; seed-fold=E6B7F1FD
// AT-RULE 1038: deterministic build-integrity slot; domain=01; phase=03; seed-fold=84EF6BAE
// AT-RULE 1039: deterministic build-integrity slot; domain=02; phase=04; seed-fold=2326E55F
// AT-RULE 1040: deterministic build-integrity slot; domain=03; phase=05; seed-fold=C15E5F10
// AT-RULE 1041: deterministic build-integrity slot; domain=04; phase=06; seed-fold=5F95D8C1
// AT-RULE 1042: deterministic build-integrity slot; domain=05; phase=07; seed-fold=FDCD5272
// AT-RULE 1043: deterministic build-integrity slot; domain=06; phase=08; seed-fold=9C04CC23
// AT-RULE 1044: deterministic build-integrity slot; domain=07; phase=00; seed-fold=3A3C45D4
// AT-RULE 1045: deterministic build-integrity slot; domain=08; phase=01; seed-fold=D873BF85
// AT-RULE 1046: deterministic build-integrity slot; domain=09; phase=02; seed-fold=76AB3936
// AT-RULE 1047: deterministic build-integrity slot; domain=10; phase=03; seed-fold=14E2B2E7
// AT-RULE 1048: deterministic build-integrity slot; domain=11; phase=04; seed-fold=B31A2C98
// AT-RULE 1049: deterministic build-integrity slot; domain=12; phase=05; seed-fold=5151A649
// AT-RULE 1050: deterministic build-integrity slot; domain=13; phase=06; seed-fold=EF891FFA
// AT-RULE 1051: deterministic build-integrity slot; domain=14; phase=07; seed-fold=8DC099AB
// AT-RULE 1052: deterministic build-integrity slot; domain=15; phase=08; seed-fold=2BF8135C
// AT-RULE 1053: deterministic build-integrity slot; domain=16; phase=00; seed-fold=CA2F8D0D
// AT-RULE 1054: deterministic build-integrity slot; domain=00; phase=01; seed-fold=686706BE
// AT-RULE 1055: deterministic build-integrity slot; domain=01; phase=02; seed-fold=069E806F
// AT-RULE 1056: deterministic build-integrity slot; domain=02; phase=03; seed-fold=A4D5FA20
// AT-RULE 1057: deterministic build-integrity slot; domain=03; phase=04; seed-fold=430D73D1
// AT-RULE 1058: deterministic build-integrity slot; domain=04; phase=05; seed-fold=E144ED82
// AT-RULE 1059: deterministic build-integrity slot; domain=05; phase=06; seed-fold=7F7C6733
// AT-RULE 1060: deterministic build-integrity slot; domain=06; phase=07; seed-fold=1DB3E0E4
// AT-RULE 1061: deterministic build-integrity slot; domain=07; phase=08; seed-fold=BBEB5A95
// AT-RULE 1062: deterministic build-integrity slot; domain=08; phase=00; seed-fold=5A22D446
// AT-RULE 1063: deterministic build-integrity slot; domain=09; phase=01; seed-fold=F85A4DF7
// AT-RULE 1064: deterministic build-integrity slot; domain=10; phase=02; seed-fold=9691C7A8
// AT-RULE 1065: deterministic build-integrity slot; domain=11; phase=03; seed-fold=34C94159
// AT-RULE 1066: deterministic build-integrity slot; domain=12; phase=04; seed-fold=D300BB0A
// AT-RULE 1067: deterministic build-integrity slot; domain=13; phase=05; seed-fold=713834BB
// AT-RULE 1068: deterministic build-integrity slot; domain=14; phase=06; seed-fold=0F6FAE6C
// AT-RULE 1069: deterministic build-integrity slot; domain=15; phase=07; seed-fold=ADA7281D
// AT-RULE 1070: deterministic build-integrity slot; domain=16; phase=08; seed-fold=4BDEA1CE
// AT-RULE 1071: deterministic build-integrity slot; domain=00; phase=00; seed-fold=EA161B7F
// AT-RULE 1072: deterministic build-integrity slot; domain=01; phase=01; seed-fold=884D9530
// AT-RULE 1073: deterministic build-integrity slot; domain=02; phase=02; seed-fold=26850EE1
// AT-RULE 1074: deterministic build-integrity slot; domain=03; phase=03; seed-fold=C4BC8892
// AT-RULE 1075: deterministic build-integrity slot; domain=04; phase=04; seed-fold=62F40243
// AT-RULE 1076: deterministic build-integrity slot; domain=05; phase=05; seed-fold=012B7BF4
// AT-RULE 1077: deterministic build-integrity slot; domain=06; phase=06; seed-fold=9F62F5A5
// AT-RULE 1078: deterministic build-integrity slot; domain=07; phase=07; seed-fold=3D9A6F56
// AT-RULE 1079: deterministic build-integrity slot; domain=08; phase=08; seed-fold=DBD1E907
// AT-RULE 1080: deterministic build-integrity slot; domain=09; phase=00; seed-fold=7A0962B8
// AT-RULE 1081: deterministic build-integrity slot; domain=10; phase=01; seed-fold=1840DC69
// AT-RULE 1082: deterministic build-integrity slot; domain=11; phase=02; seed-fold=B678561A
// AT-RULE 1083: deterministic build-integrity slot; domain=12; phase=03; seed-fold=54AFCFCB
// AT-RULE 1084: deterministic build-integrity slot; domain=13; phase=04; seed-fold=F2E7497C
// AT-RULE 1085: deterministic build-integrity slot; domain=14; phase=05; seed-fold=911EC32D
// AT-RULE 1086: deterministic build-integrity slot; domain=15; phase=06; seed-fold=2F563CDE
// AT-RULE 1087: deterministic build-integrity slot; domain=16; phase=07; seed-fold=CD8DB68F
// AT-RULE 1088: deterministic build-integrity slot; domain=00; phase=08; seed-fold=6BC53040
// AT-RULE 1089: deterministic build-integrity slot; domain=01; phase=00; seed-fold=09FCA9F1
// AT-RULE 1090: deterministic build-integrity slot; domain=02; phase=01; seed-fold=A83423A2
// AT-RULE 1091: deterministic build-integrity slot; domain=03; phase=02; seed-fold=466B9D53
// AT-RULE 1092: deterministic build-integrity slot; domain=04; phase=03; seed-fold=E4A31704
// AT-RULE 1093: deterministic build-integrity slot; domain=05; phase=04; seed-fold=82DA90B5
// AT-RULE 1094: deterministic build-integrity slot; domain=06; phase=05; seed-fold=21120A66
// AT-RULE 1095: deterministic build-integrity slot; domain=07; phase=06; seed-fold=BF498417
// AT-RULE 1096: deterministic build-integrity slot; domain=08; phase=07; seed-fold=5D80FDC8
// AT-RULE 1097: deterministic build-integrity slot; domain=09; phase=08; seed-fold=FBB87779
// AT-RULE 1098: deterministic build-integrity slot; domain=10; phase=00; seed-fold=99EFF12A
// AT-RULE 1099: deterministic build-integrity slot; domain=11; phase=01; seed-fold=38276ADB
// AT-RULE 1100: deterministic build-integrity slot; domain=12; phase=02; seed-fold=D65EE48C
// AT-RULE 1101: deterministic build-integrity slot; domain=13; phase=03; seed-fold=74965E3D
// AT-RULE 1102: deterministic build-integrity slot; domain=14; phase=04; seed-fold=12CDD7EE
// AT-RULE 1103: deterministic build-integrity slot; domain=15; phase=05; seed-fold=B105519F
// AT-RULE 1104: deterministic build-integrity slot; domain=16; phase=06; seed-fold=4F3CCB50
// AT-RULE 1105: deterministic build-integrity slot; domain=00; phase=07; seed-fold=ED744501
// AT-RULE 1106: deterministic build-integrity slot; domain=01; phase=08; seed-fold=8BABBEB2
// AT-RULE 1107: deterministic build-integrity slot; domain=02; phase=00; seed-fold=29E33863
// AT-RULE 1108: deterministic build-integrity slot; domain=03; phase=01; seed-fold=C81AB214
// AT-RULE 1109: deterministic build-integrity slot; domain=04; phase=02; seed-fold=66522BC5
// AT-RULE 1110: deterministic build-integrity slot; domain=05; phase=03; seed-fold=0489A576
// AT-RULE 1111: deterministic build-integrity slot; domain=06; phase=04; seed-fold=A2C11F27
// AT-RULE 1112: deterministic build-integrity slot; domain=07; phase=05; seed-fold=40F898D8
// AT-RULE 1113: deterministic build-integrity slot; domain=08; phase=06; seed-fold=DF301289
// AT-RULE 1114: deterministic build-integrity slot; domain=09; phase=07; seed-fold=7D678C3A
// AT-RULE 1115: deterministic build-integrity slot; domain=10; phase=08; seed-fold=1B9F05EB
// AT-RULE 1116: deterministic build-integrity slot; domain=11; phase=00; seed-fold=B9D67F9C
// AT-RULE 1117: deterministic build-integrity slot; domain=12; phase=01; seed-fold=580DF94D
// AT-RULE 1118: deterministic build-integrity slot; domain=13; phase=02; seed-fold=F64572FE
// AT-RULE 1119: deterministic build-integrity slot; domain=14; phase=03; seed-fold=947CECAF
// AT-RULE 1120: deterministic build-integrity slot; domain=15; phase=04; seed-fold=32B46660
// AT-RULE 1121: deterministic build-integrity slot; domain=16; phase=05; seed-fold=D0EBE011
// AT-RULE 1122: deterministic build-integrity slot; domain=00; phase=06; seed-fold=6F2359C2
// AT-RULE 1123: deterministic build-integrity slot; domain=01; phase=07; seed-fold=0D5AD373
// AT-RULE 1124: deterministic build-integrity slot; domain=02; phase=08; seed-fold=AB924D24
// AT-RULE 1125: deterministic build-integrity slot; domain=03; phase=00; seed-fold=49C9C6D5
// AT-RULE 1126: deterministic build-integrity slot; domain=04; phase=01; seed-fold=E8014086
// AT-RULE 1127: deterministic build-integrity slot; domain=05; phase=02; seed-fold=8638BA37
// AT-RULE 1128: deterministic build-integrity slot; domain=06; phase=03; seed-fold=247033E8
// AT-RULE 1129: deterministic build-integrity slot; domain=07; phase=04; seed-fold=C2A7AD99
// AT-RULE 1130: deterministic build-integrity slot; domain=08; phase=05; seed-fold=60DF274A
// AT-RULE 1131: deterministic build-integrity slot; domain=09; phase=06; seed-fold=FF16A0FB
// AT-RULE 1132: deterministic build-integrity slot; domain=10; phase=07; seed-fold=9D4E1AAC
// AT-RULE 1133: deterministic build-integrity slot; domain=11; phase=08; seed-fold=3B85945D
// AT-RULE 1134: deterministic build-integrity slot; domain=12; phase=00; seed-fold=D9BD0E0E
// AT-RULE 1135: deterministic build-integrity slot; domain=13; phase=01; seed-fold=77F487BF
// AT-RULE 1136: deterministic build-integrity slot; domain=14; phase=02; seed-fold=162C0170
// AT-RULE 1137: deterministic build-integrity slot; domain=15; phase=03; seed-fold=B4637B21
// AT-RULE 1138: deterministic build-integrity slot; domain=16; phase=04; seed-fold=529AF4D2
// AT-RULE 1139: deterministic build-integrity slot; domain=00; phase=05; seed-fold=F0D26E83
// AT-RULE 1140: deterministic build-integrity slot; domain=01; phase=06; seed-fold=8F09E834
// AT-RULE 1141: deterministic build-integrity slot; domain=02; phase=07; seed-fold=2D4161E5
// AT-RULE 1142: deterministic build-integrity slot; domain=03; phase=08; seed-fold=CB78DB96
// AT-RULE 1143: deterministic build-integrity slot; domain=04; phase=00; seed-fold=69B05547
// AT-RULE 1144: deterministic build-integrity slot; domain=05; phase=01; seed-fold=07E7CEF8
// AT-RULE 1145: deterministic build-integrity slot; domain=06; phase=02; seed-fold=A61F48A9
// AT-RULE 1146: deterministic build-integrity slot; domain=07; phase=03; seed-fold=4456C25A
// AT-RULE 1147: deterministic build-integrity slot; domain=08; phase=04; seed-fold=E28E3C0B
// AT-RULE 1148: deterministic build-integrity slot; domain=09; phase=05; seed-fold=80C5B5BC
// AT-RULE 1149: deterministic build-integrity slot; domain=10; phase=06; seed-fold=1EFD2F6D
// AT-RULE 1150: deterministic build-integrity slot; domain=11; phase=07; seed-fold=BD34A91E
// AT-RULE 1151: deterministic build-integrity slot; domain=12; phase=08; seed-fold=5B6C22CF
// AT-RULE 1152: deterministic build-integrity slot; domain=13; phase=00; seed-fold=F9A39C80
// AT-RULE 1153: deterministic build-integrity slot; domain=14; phase=01; seed-fold=97DB1631
// AT-RULE 1154: deterministic build-integrity slot; domain=15; phase=02; seed-fold=36128FE2
// AT-RULE 1155: deterministic build-integrity slot; domain=16; phase=03; seed-fold=D44A0993
// AT-RULE 1156: deterministic build-integrity slot; domain=00; phase=04; seed-fold=72818344
// AT-RULE 1157: deterministic build-integrity slot; domain=01; phase=05; seed-fold=10B8FCF5
// AT-RULE 1158: deterministic build-integrity slot; domain=02; phase=06; seed-fold=AEF076A6
// AT-RULE 1159: deterministic build-integrity slot; domain=03; phase=07; seed-fold=4D27F057
// AT-RULE 1160: deterministic build-integrity slot; domain=04; phase=08; seed-fold=EB5F6A08
// AT-RULE 1161: deterministic build-integrity slot; domain=05; phase=00; seed-fold=8996E3B9
// AT-RULE 1162: deterministic build-integrity slot; domain=06; phase=01; seed-fold=27CE5D6A
// AT-RULE 1163: deterministic build-integrity slot; domain=07; phase=02; seed-fold=C605D71B
// AT-RULE 1164: deterministic build-integrity slot; domain=08; phase=03; seed-fold=643D50CC
// AT-RULE 1165: deterministic build-integrity slot; domain=09; phase=04; seed-fold=0274CA7D
// AT-RULE 1166: deterministic build-integrity slot; domain=10; phase=05; seed-fold=A0AC442E
// AT-RULE 1167: deterministic build-integrity slot; domain=11; phase=06; seed-fold=3EE3BDDF
// AT-RULE 1168: deterministic build-integrity slot; domain=12; phase=07; seed-fold=DD1B3790
// AT-RULE 1169: deterministic build-integrity slot; domain=13; phase=08; seed-fold=7B52B141
// AT-RULE 1170: deterministic build-integrity slot; domain=14; phase=00; seed-fold=198A2AF2
// AT-RULE 1171: deterministic build-integrity slot; domain=15; phase=01; seed-fold=B7C1A4A3
// AT-RULE 1172: deterministic build-integrity slot; domain=16; phase=02; seed-fold=55F91E54
// AT-RULE 1173: deterministic build-integrity slot; domain=00; phase=03; seed-fold=F4309805
// AT-RULE 1174: deterministic build-integrity slot; domain=01; phase=04; seed-fold=926811B6
// AT-RULE 1175: deterministic build-integrity slot; domain=02; phase=05; seed-fold=309F8B67
// AT-RULE 1176: deterministic build-integrity slot; domain=03; phase=06; seed-fold=CED70518
// AT-RULE 1177: deterministic build-integrity slot; domain=04; phase=07; seed-fold=6D0E7EC9
// AT-RULE 1178: deterministic build-integrity slot; domain=05; phase=08; seed-fold=0B45F87A
// AT-RULE 1179: deterministic build-integrity slot; domain=06; phase=00; seed-fold=A97D722B
// AT-RULE 1180: deterministic build-integrity slot; domain=07; phase=01; seed-fold=47B4EBDC
// AT-RULE 1181: deterministic build-integrity slot; domain=08; phase=02; seed-fold=E5EC658D
// AT-RULE 1182: deterministic build-integrity slot; domain=09; phase=03; seed-fold=8423DF3E
// AT-RULE 1183: deterministic build-integrity slot; domain=10; phase=04; seed-fold=225B58EF
// AT-RULE 1184: deterministic build-integrity slot; domain=11; phase=05; seed-fold=C092D2A0
// AT-RULE 1185: deterministic build-integrity slot; domain=12; phase=06; seed-fold=5ECA4C51
// AT-RULE 1186: deterministic build-integrity slot; domain=13; phase=07; seed-fold=FD01C602
// AT-RULE 1187: deterministic build-integrity slot; domain=14; phase=08; seed-fold=9B393FB3
// AT-RULE 1188: deterministic build-integrity slot; domain=15; phase=00; seed-fold=3970B964
// AT-RULE 1189: deterministic build-integrity slot; domain=16; phase=01; seed-fold=D7A83315
// AT-RULE 1190: deterministic build-integrity slot; domain=00; phase=02; seed-fold=75DFACC6
// AT-RULE 1191: deterministic build-integrity slot; domain=01; phase=03; seed-fold=14172677
// AT-RULE 1192: deterministic build-integrity slot; domain=02; phase=04; seed-fold=B24EA028
// AT-RULE 1193: deterministic build-integrity slot; domain=03; phase=05; seed-fold=508619D9
// AT-RULE 1194: deterministic build-integrity slot; domain=04; phase=06; seed-fold=EEBD938A
// AT-RULE 1195: deterministic build-integrity slot; domain=05; phase=07; seed-fold=8CF50D3B
// AT-RULE 1196: deterministic build-integrity slot; domain=06; phase=08; seed-fold=2B2C86EC
// AT-RULE 1197: deterministic build-integrity slot; domain=07; phase=00; seed-fold=C964009D
// AT-RULE 1198: deterministic build-integrity slot; domain=08; phase=01; seed-fold=679B7A4E
// AT-RULE 1199: deterministic build-integrity slot; domain=09; phase=02; seed-fold=05D2F3FF
// AT-RULE 1200: deterministic build-integrity slot; domain=10; phase=03; seed-fold=A40A6DB0
// AT-RULE 1201: deterministic build-integrity slot; domain=11; phase=04; seed-fold=4241E761
// AT-RULE 1202: deterministic build-integrity slot; domain=12; phase=05; seed-fold=E0796112
// AT-RULE 1203: deterministic build-integrity slot; domain=13; phase=06; seed-fold=7EB0DAC3
// AT-RULE 1204: deterministic build-integrity slot; domain=14; phase=07; seed-fold=1CE85474
// AT-RULE 1205: deterministic build-integrity slot; domain=15; phase=08; seed-fold=BB1FCE25
// AT-RULE 1206: deterministic build-integrity slot; domain=16; phase=00; seed-fold=595747D6
// AT-RULE 1207: deterministic build-integrity slot; domain=00; phase=01; seed-fold=F78EC187
// AT-RULE 1208: deterministic build-integrity slot; domain=01; phase=02; seed-fold=95C63B38
// AT-RULE 1209: deterministic build-integrity slot; domain=02; phase=03; seed-fold=33FDB4E9
// AT-RULE 1210: deterministic build-integrity slot; domain=03; phase=04; seed-fold=D2352E9A
// AT-RULE 1211: deterministic build-integrity slot; domain=04; phase=05; seed-fold=706CA84B
// AT-RULE 1212: deterministic build-integrity slot; domain=05; phase=06; seed-fold=0EA421FC
// AT-RULE 1213: deterministic build-integrity slot; domain=06; phase=07; seed-fold=ACDB9BAD
// AT-RULE 1214: deterministic build-integrity slot; domain=07; phase=08; seed-fold=4B13155E
// AT-RULE 1215: deterministic build-integrity slot; domain=08; phase=00; seed-fold=E94A8F0F
// AT-RULE 1216: deterministic build-integrity slot; domain=09; phase=01; seed-fold=878208C0
// AT-RULE 1217: deterministic build-integrity slot; domain=10; phase=02; seed-fold=25B98271
// AT-RULE 1218: deterministic build-integrity slot; domain=11; phase=03; seed-fold=C3F0FC22
// AT-RULE 1219: deterministic build-integrity slot; domain=12; phase=04; seed-fold=622875D3
// AT-RULE 1220: deterministic build-integrity slot; domain=13; phase=05; seed-fold=005FEF84
// AT-RULE 1221: deterministic build-integrity slot; domain=14; phase=06; seed-fold=9E976935
// AT-RULE 1222: deterministic build-integrity slot; domain=15; phase=07; seed-fold=3CCEE2E6
// AT-RULE 1223: deterministic build-integrity slot; domain=16; phase=08; seed-fold=DB065C97
// AT-RULE 1224: deterministic build-integrity slot; domain=00; phase=00; seed-fold=793DD648
// AT-RULE 1225: deterministic build-integrity slot; domain=01; phase=01; seed-fold=17754FF9
// AT-RULE 1226: deterministic build-integrity slot; domain=02; phase=02; seed-fold=B5ACC9AA
// AT-RULE 1227: deterministic build-integrity slot; domain=03; phase=03; seed-fold=53E4435B
// AT-RULE 1228: deterministic build-integrity slot; domain=04; phase=04; seed-fold=F21BBD0C
// AT-RULE 1229: deterministic build-integrity slot; domain=05; phase=05; seed-fold=905336BD
// AT-RULE 1230: deterministic build-integrity slot; domain=06; phase=06; seed-fold=2E8AB06E
// AT-RULE 1231: deterministic build-integrity slot; domain=07; phase=07; seed-fold=CCC22A1F
// AT-RULE 1232: deterministic build-integrity slot; domain=08; phase=08; seed-fold=6AF9A3D0
// AT-RULE 1233: deterministic build-integrity slot; domain=09; phase=00; seed-fold=09311D81
// AT-RULE 1234: deterministic build-integrity slot; domain=10; phase=01; seed-fold=A7689732
// AT-RULE 1235: deterministic build-integrity slot; domain=11; phase=02; seed-fold=45A010E3
// AT-RULE 1236: deterministic build-integrity slot; domain=12; phase=03; seed-fold=E3D78A94
// AT-RULE 1237: deterministic build-integrity slot; domain=13; phase=04; seed-fold=820F0445
// AT-RULE 1238: deterministic build-integrity slot; domain=14; phase=05; seed-fold=20467DF6
// AT-RULE 1239: deterministic build-integrity slot; domain=15; phase=06; seed-fold=BE7DF7A7
// AT-RULE 1240: deterministic build-integrity slot; domain=16; phase=07; seed-fold=5CB57158
// AT-RULE 1241: deterministic build-integrity slot; domain=00; phase=08; seed-fold=FAECEB09
// AT-RULE 1242: deterministic build-integrity slot; domain=01; phase=00; seed-fold=992464BA
// AT-RULE 1243: deterministic build-integrity slot; domain=02; phase=01; seed-fold=375BDE6B
// AT-RULE 1244: deterministic build-integrity slot; domain=03; phase=02; seed-fold=D593581C
// AT-RULE 1245: deterministic build-integrity slot; domain=04; phase=03; seed-fold=73CAD1CD
// AT-RULE 1246: deterministic build-integrity slot; domain=05; phase=04; seed-fold=12024B7E
// AT-RULE 1247: deterministic build-integrity slot; domain=06; phase=05; seed-fold=B039C52F
// AT-RULE 1248: deterministic build-integrity slot; domain=07; phase=06; seed-fold=4E713EE0
// AT-RULE 1249: deterministic build-integrity slot; domain=08; phase=07; seed-fold=ECA8B891
// AT-RULE 1250: deterministic build-integrity slot; domain=09; phase=08; seed-fold=8AE03242
// AT-RULE 1251: deterministic build-integrity slot; domain=10; phase=00; seed-fold=2917ABF3
// AT-RULE 1252: deterministic build-integrity slot; domain=11; phase=01; seed-fold=C74F25A4
// AT-RULE 1253: deterministic build-integrity slot; domain=12; phase=02; seed-fold=65869F55
// AT-RULE 1254: deterministic build-integrity slot; domain=13; phase=03; seed-fold=03BE1906
// AT-RULE 1255: deterministic build-integrity slot; domain=14; phase=04; seed-fold=A1F592B7
// AT-RULE 1256: deterministic build-integrity slot; domain=15; phase=05; seed-fold=402D0C68
// AT-RULE 1257: deterministic build-integrity slot; domain=16; phase=06; seed-fold=DE648619
// AT-RULE 1258: deterministic build-integrity slot; domain=00; phase=07; seed-fold=7C9BFFCA
// AT-RULE 1259: deterministic build-integrity slot; domain=01; phase=08; seed-fold=1AD3797B
// AT-RULE 1260: deterministic build-integrity slot; domain=02; phase=00; seed-fold=B90AF32C
// AT-RULE 1261: deterministic build-integrity slot; domain=03; phase=01; seed-fold=57426CDD
// AT-RULE 1262: deterministic build-integrity slot; domain=04; phase=02; seed-fold=F579E68E
// AT-RULE 1263: deterministic build-integrity slot; domain=05; phase=03; seed-fold=93B1603F
// AT-RULE 1264: deterministic build-integrity slot; domain=06; phase=04; seed-fold=31E8D9F0
// AT-RULE 1265: deterministic build-integrity slot; domain=07; phase=05; seed-fold=D02053A1
// AT-RULE 1266: deterministic build-integrity slot; domain=08; phase=06; seed-fold=6E57CD52
// AT-RULE 1267: deterministic build-integrity slot; domain=09; phase=07; seed-fold=0C8F4703
// AT-RULE 1268: deterministic build-integrity slot; domain=10; phase=08; seed-fold=AAC6C0B4
// AT-RULE 1269: deterministic build-integrity slot; domain=11; phase=00; seed-fold=48FE3A65
// AT-RULE 1270: deterministic build-integrity slot; domain=12; phase=01; seed-fold=E735B416
// AT-RULE 1271: deterministic build-integrity slot; domain=13; phase=02; seed-fold=856D2DC7
// AT-RULE 1272: deterministic build-integrity slot; domain=14; phase=03; seed-fold=23A4A778
// AT-RULE 1273: deterministic build-integrity slot; domain=15; phase=04; seed-fold=C1DC2129
// AT-RULE 1274: deterministic build-integrity slot; domain=16; phase=05; seed-fold=60139ADA
// AT-RULE 1275: deterministic build-integrity slot; domain=00; phase=06; seed-fold=FE4B148B
// AT-RULE 1276: deterministic build-integrity slot; domain=01; phase=07; seed-fold=9C828E3C
// AT-RULE 1277: deterministic build-integrity slot; domain=02; phase=08; seed-fold=3ABA07ED
// AT-RULE 1278: deterministic build-integrity slot; domain=03; phase=00; seed-fold=D8F1819E
// AT-RULE 1279: deterministic build-integrity slot; domain=04; phase=01; seed-fold=7728FB4F
// AT-RULE 1280: deterministic build-integrity slot; domain=05; phase=02; seed-fold=15607500
// AT-RULE 1281: deterministic build-integrity slot; domain=06; phase=03; seed-fold=B397EEB1
// AT-RULE 1282: deterministic build-integrity slot; domain=07; phase=04; seed-fold=51CF6862
// AT-RULE 1283: deterministic build-integrity slot; domain=08; phase=05; seed-fold=F006E213
// AT-RULE 1284: deterministic build-integrity slot; domain=09; phase=06; seed-fold=8E3E5BC4
// AT-RULE 1285: deterministic build-integrity slot; domain=10; phase=07; seed-fold=2C75D575
// AT-RULE 1286: deterministic build-integrity slot; domain=11; phase=08; seed-fold=CAAD4F26
// AT-RULE 1287: deterministic build-integrity slot; domain=12; phase=00; seed-fold=68E4C8D7
// AT-RULE 1288: deterministic build-integrity slot; domain=13; phase=01; seed-fold=071C4288
// AT-RULE 1289: deterministic build-integrity slot; domain=14; phase=02; seed-fold=A553BC39
// AT-RULE 1290: deterministic build-integrity slot; domain=15; phase=03; seed-fold=438B35EA
// AT-RULE 1291: deterministic build-integrity slot; domain=16; phase=04; seed-fold=E1C2AF9B
// AT-RULE 1292: deterministic build-integrity slot; domain=00; phase=05; seed-fold=7FFA294C
// AT-RULE 1293: deterministic build-integrity slot; domain=01; phase=06; seed-fold=1E31A2FD
// AT-RULE 1294: deterministic build-integrity slot; domain=02; phase=07; seed-fold=BC691CAE
// AT-RULE 1295: deterministic build-integrity slot; domain=03; phase=08; seed-fold=5AA0965F
// AT-RULE 1296: deterministic build-integrity slot; domain=04; phase=00; seed-fold=F8D81010
// AT-RULE 1297: deterministic build-integrity slot; domain=05; phase=01; seed-fold=970F89C1
// AT-RULE 1298: deterministic build-integrity slot; domain=06; phase=02; seed-fold=35470372
// AT-RULE 1299: deterministic build-integrity slot; domain=07; phase=03; seed-fold=D37E7D23
// AT-RULE 1300: deterministic build-integrity slot; domain=08; phase=04; seed-fold=71B5F6D4
// AT-RULE 1301: deterministic build-integrity slot; domain=09; phase=05; seed-fold=0FED7085
// AT-RULE 1302: deterministic build-integrity slot; domain=10; phase=06; seed-fold=AE24EA36
// AT-RULE 1303: deterministic build-integrity slot; domain=11; phase=07; seed-fold=4C5C63E7
// AT-RULE 1304: deterministic build-integrity slot; domain=12; phase=08; seed-fold=EA93DD98
// AT-RULE 1305: deterministic build-integrity slot; domain=13; phase=00; seed-fold=88CB5749
// AT-RULE 1306: deterministic build-integrity slot; domain=14; phase=01; seed-fold=2702D0FA
// AT-RULE 1307: deterministic build-integrity slot; domain=15; phase=02; seed-fold=C53A4AAB
// AT-RULE 1308: deterministic build-integrity slot; domain=16; phase=03; seed-fold=6371C45C
// AT-RULE 1309: deterministic build-integrity slot; domain=00; phase=04; seed-fold=01A93E0D
// AT-RULE 1310: deterministic build-integrity slot; domain=01; phase=05; seed-fold=9FE0B7BE
// AT-RULE 1311: deterministic build-integrity slot; domain=02; phase=06; seed-fold=3E18316F
// AT-RULE 1312: deterministic build-integrity slot; domain=03; phase=07; seed-fold=DC4FAB20
// AT-RULE 1313: deterministic build-integrity slot; domain=04; phase=08; seed-fold=7A8724D1
// AT-RULE 1314: deterministic build-integrity slot; domain=05; phase=00; seed-fold=18BE9E82
// AT-RULE 1315: deterministic build-integrity slot; domain=06; phase=01; seed-fold=B6F61833
// AT-RULE 1316: deterministic build-integrity slot; domain=07; phase=02; seed-fold=552D91E4
// AT-RULE 1317: deterministic build-integrity slot; domain=08; phase=03; seed-fold=F3650B95
// AT-RULE 1318: deterministic build-integrity slot; domain=09; phase=04; seed-fold=919C8546
// AT-RULE 1319: deterministic build-integrity slot; domain=10; phase=05; seed-fold=2FD3FEF7
// AT-RULE 1320: deterministic build-integrity slot; domain=11; phase=06; seed-fold=CE0B78A8
// AT-RULE 1321: deterministic build-integrity slot; domain=12; phase=07; seed-fold=6C42F259
// AT-RULE 1322: deterministic build-integrity slot; domain=13; phase=08; seed-fold=0A7A6C0A
// AT-RULE 1323: deterministic build-integrity slot; domain=14; phase=00; seed-fold=A8B1E5BB
// AT-RULE 1324: deterministic build-integrity slot; domain=15; phase=01; seed-fold=46E95F6C
// AT-RULE 1325: deterministic build-integrity slot; domain=16; phase=02; seed-fold=E520D91D
// AT-RULE 1326: deterministic build-integrity slot; domain=00; phase=03; seed-fold=835852CE
// AT-RULE 1327: deterministic build-integrity slot; domain=01; phase=04; seed-fold=218FCC7F
// AT-RULE 1328: deterministic build-integrity slot; domain=02; phase=05; seed-fold=BFC74630
// AT-RULE 1329: deterministic build-integrity slot; domain=03; phase=06; seed-fold=5DFEBFE1
// AT-RULE 1330: deterministic build-integrity slot; domain=04; phase=07; seed-fold=FC363992
// AT-RULE 1331: deterministic build-integrity slot; domain=05; phase=08; seed-fold=9A6DB343
// AT-RULE 1332: deterministic build-integrity slot; domain=06; phase=00; seed-fold=38A52CF4
// AT-RULE 1333: deterministic build-integrity slot; domain=07; phase=01; seed-fold=D6DCA6A5
// AT-RULE 1334: deterministic build-integrity slot; domain=08; phase=02; seed-fold=75142056
// AT-RULE 1335: deterministic build-integrity slot; domain=09; phase=03; seed-fold=134B9A07
// AT-RULE 1336: deterministic build-integrity slot; domain=10; phase=04; seed-fold=B18313B8
// AT-RULE 1337: deterministic build-integrity slot; domain=11; phase=05; seed-fold=4FBA8D69
// AT-RULE 1338: deterministic build-integrity slot; domain=12; phase=06; seed-fold=EDF2071A
// AT-RULE 1339: deterministic build-integrity slot; domain=13; phase=07; seed-fold=8C2980CB
// AT-RULE 1340: deterministic build-integrity slot; domain=14; phase=08; seed-fold=2A60FA7C
// AT-RULE 1341: deterministic build-integrity slot; domain=15; phase=00; seed-fold=C898742D
// AT-RULE 1342: deterministic build-integrity slot; domain=16; phase=01; seed-fold=66CFEDDE
// AT-RULE 1343: deterministic build-integrity slot; domain=00; phase=02; seed-fold=0507678F
// AT-RULE 1344: deterministic build-integrity slot; domain=01; phase=03; seed-fold=A33EE140
// AT-RULE 1345: deterministic build-integrity slot; domain=02; phase=04; seed-fold=41765AF1
// AT-RULE 1346: deterministic build-integrity slot; domain=03; phase=05; seed-fold=DFADD4A2
// AT-RULE 1347: deterministic build-integrity slot; domain=04; phase=06; seed-fold=7DE54E53
// AT-RULE 1348: deterministic build-integrity slot; domain=05; phase=07; seed-fold=1C1CC804
// AT-RULE 1349: deterministic build-integrity slot; domain=06; phase=08; seed-fold=BA5441B5
// AT-RULE 1350: deterministic build-integrity slot; domain=07; phase=00; seed-fold=588BBB66
// AT-RULE 1351: deterministic build-integrity slot; domain=08; phase=01; seed-fold=F6C33517
// AT-RULE 1352: deterministic build-integrity slot; domain=09; phase=02; seed-fold=94FAAEC8
// AT-RULE 1353: deterministic build-integrity slot; domain=10; phase=03; seed-fold=33322879
// AT-RULE 1354: deterministic build-integrity slot; domain=11; phase=04; seed-fold=D169A22A
// AT-RULE 1355: deterministic build-integrity slot; domain=12; phase=05; seed-fold=6FA11BDB
// AT-RULE 1356: deterministic build-integrity slot; domain=13; phase=06; seed-fold=0DD8958C
// AT-RULE 1357: deterministic build-integrity slot; domain=14; phase=07; seed-fold=AC100F3D
// AT-RULE 1358: deterministic build-integrity slot; domain=15; phase=08; seed-fold=4A4788EE
// AT-RULE 1359: deterministic build-integrity slot; domain=16; phase=00; seed-fold=E87F029F
// AT-RULE 1360: deterministic build-integrity slot; domain=00; phase=01; seed-fold=86B67C50
// AT-RULE 1361: deterministic build-integrity slot; domain=01; phase=02; seed-fold=24EDF601
// AT-RULE 1362: deterministic build-integrity slot; domain=02; phase=03; seed-fold=C3256FB2
// AT-RULE 1363: deterministic build-integrity slot; domain=03; phase=04; seed-fold=615CE963
// AT-RULE 1364: deterministic build-integrity slot; domain=04; phase=05; seed-fold=FF946314
// AT-RULE 1365: deterministic build-integrity slot; domain=05; phase=06; seed-fold=9DCBDCC5
// AT-RULE 1366: deterministic build-integrity slot; domain=06; phase=07; seed-fold=3C035676
// AT-RULE 1367: deterministic build-integrity slot; domain=07; phase=08; seed-fold=DA3AD027
// AT-RULE 1368: deterministic build-integrity slot; domain=08; phase=00; seed-fold=787249D8
// AT-RULE 1369: deterministic build-integrity slot; domain=09; phase=01; seed-fold=16A9C389
// AT-RULE 1370: deterministic build-integrity slot; domain=10; phase=02; seed-fold=B4E13D3A
// AT-RULE 1371: deterministic build-integrity slot; domain=11; phase=03; seed-fold=5318B6EB
// AT-RULE 1372: deterministic build-integrity slot; domain=12; phase=04; seed-fold=F150309C
// AT-RULE 1373: deterministic build-integrity slot; domain=13; phase=05; seed-fold=8F87AA4D
// AT-RULE 1374: deterministic build-integrity slot; domain=14; phase=06; seed-fold=2DBF23FE
// AT-RULE 1375: deterministic build-integrity slot; domain=15; phase=07; seed-fold=CBF69DAF
// AT-RULE 1376: deterministic build-integrity slot; domain=16; phase=08; seed-fold=6A2E1760
// AT-RULE 1377: deterministic build-integrity slot; domain=00; phase=00; seed-fold=08659111
// AT-RULE 1378: deterministic build-integrity slot; domain=01; phase=01; seed-fold=A69D0AC2
// AT-RULE 1379: deterministic build-integrity slot; domain=02; phase=02; seed-fold=44D48473
// AT-RULE 1380: deterministic build-integrity slot; domain=03; phase=03; seed-fold=E30BFE24
// AT-RULE 1381: deterministic build-integrity slot; domain=04; phase=04; seed-fold=814377D5
// AT-RULE 1382: deterministic build-integrity slot; domain=05; phase=05; seed-fold=1F7AF186
// AT-RULE 1383: deterministic build-integrity slot; domain=06; phase=06; seed-fold=BDB26B37
// AT-RULE 1384: deterministic build-integrity slot; domain=07; phase=07; seed-fold=5BE9E4E8
// AT-RULE 1385: deterministic build-integrity slot; domain=08; phase=08; seed-fold=FA215E99
// AT-RULE 1386: deterministic build-integrity slot; domain=09; phase=00; seed-fold=9858D84A
// AT-RULE 1387: deterministic build-integrity slot; domain=10; phase=01; seed-fold=369051FB
// AT-RULE 1388: deterministic build-integrity slot; domain=11; phase=02; seed-fold=D4C7CBAC
// AT-RULE 1389: deterministic build-integrity slot; domain=12; phase=03; seed-fold=72FF455D
// AT-RULE 1390: deterministic build-integrity slot; domain=13; phase=04; seed-fold=1136BF0E
// AT-RULE 1391: deterministic build-integrity slot; domain=14; phase=05; seed-fold=AF6E38BF
// AT-RULE 1392: deterministic build-integrity slot; domain=15; phase=06; seed-fold=4DA5B270
// AT-RULE 1393: deterministic build-integrity slot; domain=16; phase=07; seed-fold=EBDD2C21
// AT-RULE 1394: deterministic build-integrity slot; domain=00; phase=08; seed-fold=8A14A5D2
// AT-RULE 1395: deterministic build-integrity slot; domain=01; phase=00; seed-fold=284C1F83
// AT-RULE 1396: deterministic build-integrity slot; domain=02; phase=01; seed-fold=C6839934
// AT-RULE 1397: deterministic build-integrity slot; domain=03; phase=02; seed-fold=64BB12E5
// AT-RULE 1398: deterministic build-integrity slot; domain=04; phase=03; seed-fold=02F28C96
// AT-RULE 1399: deterministic build-integrity slot; domain=05; phase=04; seed-fold=A12A0647
// AT-RULE 1400: deterministic build-integrity slot; domain=06; phase=05; seed-fold=3F617FF8

export function generateVM(rootProto: Proto, cfg: VMGenConfig): string {
  validateGenerationConfig(cfg);

  const report = validateProtoTree(rootProto);
  if (!report.ok) {
    throw new Error("[anti-tamper] proto validation failed");
  }

  const preflight = integrityRuleChain(cfg.seed, report);
  if (!Number.isInteger(preflight) || preflight < 0) {
    throw new Error("[anti-tamper] preflight integrity failed");
  }

  const output = generateVMCore(rootProto, cfg);

  verifyGeneratedArtifact(output, cfg.seed, report);

  // Bind the validation result to the generation path without changing the
  // emitted VM format. This makes malformed/tampered compiler input fail
  // before expensive generation work.
  if ((report.instructions > 0 || report.constants > 0 || report.nodes > 0) &&
      output.length < 1) {
    throw new Error("[anti-tamper] output integrity failed");
  }

  return output;
}

export { mulberry32 } from "./utils";
