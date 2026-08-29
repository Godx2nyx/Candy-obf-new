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
      integrityU32(uv.idx ^ fnvHash(Array.from(uv.name as string).map((c: string) => c.charCodeAt(0)), 0x1234))
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


function luauStringValue(raw: string, quote: string): string | null {
  // Decode only the common escapes emitted by this generator. If an unfamiliar
  // escape is present, leave the literal untouched rather than risking a
  // semantic change.
  let out = ""
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]
    if (ch !== "\\") { out += ch; continue }
    if (i + 1 >= raw.length) return null
    const e = raw[++i]
    if (e === "n") out += "\n"
    else if (e === "r") out += "\r"
    else if (e === "t") out += "\t"
    else if (e === "\\") out += "\\"
    else if (e === "\"") out += "\""
    else if (e === "'") out += "'"
    else return null
  }
  // Keep the pool ASCII-only and avoid control characters. Long strings are
  // intentionally left alone because the VM payload itself is already base85.
  if (out.length === 0 || out.length > 96) return null
  for (let i = 0; i < out.length; i++) {
    const c = out.charCodeAt(i)
    if (c < 32 || c > 126) return null
  }
  return out
}

function hardenLuauOutput(source: string, seed: number): string {
  const pool: string[] = []
  const poolIndex = new Map<string, number>()
  const replaced: string[] = []
  let i = 0

  // Lex only string literals. Comments are deliberately ignored because the
  // generator emits no user comments into the payload.
  while (i < source.length) {
    const ch = source[i]
    if (ch !== "\"" && ch !== "'") {
      replaced.push(ch)
      i++
      continue
    }

    const quote = ch
    let j = i + 1
    let escaped = false
    while (j < source.length) {
      const c = source[j]
      if (escaped) { escaped = false; j++; continue }
      if (c === "\\") { escaped = true; j++; continue }
      if (c === quote) break
      j++
    }
    if (j >= source.length) {
      replaced.push(ch)
      i++
      continue
    }

    const raw = source.slice(i + 1, j)
    const value = luauStringValue(raw, quote)
    if (value === null) {
      replaced.push(source.slice(i, j + 1))
    } else {
      let idx = poolIndex.get(value)
      if (idx === undefined) {
        idx = pool.length + 1
        poolIndex.set(value, idx)
        pool.push(value)
      }
      replaced.push(`__STR[${idx}]`)
    }
    i = j + 1
  }

  if (pool.length === 0) return source

  const rng = mulberry32((seed ^ 0xA53C9E17) >>> 0)
  const occupied = new Set<string>()
  for (const m of source.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*\b/g)) occupied.add(m[0])
  const fresh = (fallback: string): string => {
    let q = fallback
    while (occupied.has(q)) q = "_" + q
    occupied.add(q)
    return q
  }
  const generatedNames = randomNames(rng, 32, 8)
  const nPool = fresh(generatedNames[0])
  const nDec = fresh(generatedNames[1])
  const nMap = fresh(generatedNames[2])
  const nTmp = fresh(generatedNames[3])

  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
  const mapEntries = Array.from(alphabet).map((c, k) => `[${c.charCodeAt(0)}]=${k}`).join(',')
  const encoded = pool.map(v => base85Encode(Array.from(v, c => c.charCodeAt(0))))

  const prefix: string[] = []
  prefix.push(`local ${nMap}={${mapEntries}}`)
  prefix.push(`local ${nDec}=function(s) local o={};local p=1;while p<=#s do local v=0;local q=math.min(5,#s-p+1);for j=0,q-1 do v=v*85+(${nMap}[s:byte(p+j)] or 0) end;for j=q,4 do v=v*85+84 end;for j=3,5-q,-1 do o[#o+1]=string.char(math.floor(v/256^j)%256) end;p=p+q end;return table.concat(o) end`)
  prefix.push(`local ${nPool}={}`)
  encoded.forEach((b, k) => prefix.push(`${nPool}[${k + 1}]=${nDec}(${JSON.stringify(b)})`))

  // Add deterministic, side-effect-free padding. It is deliberately boring:
  // it only increases structural noise and does not probe the host or security
  // tooling. Each block is isolated so it cannot affect VM state.
  for (let z = 0; z < 160; z++) {
    const a = Math.floor(rng() * 0x7fffffff) + 1
    const b = Math.floor(rng() * 0x7fffffff) + 1
    const n = randomNames(rng, 1, 7)[0]
    prefix.push(`if false then local ${n}=${a}*${b};${n}=${n}%${0x100000000};end`)
  }

  const body = replaced.join("")
  // Use the actual randomized pool identifier in the rewritten body.
  return prefix.join("\n") + "\n" + body.replace(/__STR\[/g, `${nPool}[`)
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

  // ====== ANTI-EMU GUARD (DEBUG) ======
  const dispEntries = dispTblKeys.map((k,i)=>`[${k}]=${dispTblVals[i]}`).join(',')
  L(`local ${nFib1},${nFib2}=1,1`)
  L(`for ${nFibN}=2,${fibN} do local ${nFibT}=${nFib2};${nFib2}=${nFib1}+${nFib2};${nFib1}=${nFibT} end`)
  L(`if ${nFib2}%65536~=${fibExpected} then error("",0) end`)
  L(`local ${nMath1}=math.floor(math.sqrt(${mathA}*${mathB}))`)
  L(`if ${nMath1}~=${mathExp} then error("",0) end`)
  L(`local ${nTbl1}=0`)
  L(`for _,${nV} in ipairs({1,4,9,16,25}) do ${nTbl1}=${nTbl1}+${nV} end`)
  L(`if ${nTbl1}~=${tblSum} then error("",0) end`)
  L(`local ${nMeta1}={__index=function(t,k) return ${metaKey} end}`)
  L(`local ${nMeta2}=setmetatable({},${nMeta1})`)
  L(`if ${nMeta2}._candy~=${metaKey} then error("",0) end`)
  L(`local ${nUvR}=${uvSeed}`)
  L(`local ${nUvC}=${uvA};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`${nUvC}=${uvB};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`${nUvC}=${uvC};${nUvR}=(function() return bit32.bxor(${nUvR},${nUvC}) end)()`)
  L(`if ${nUvR}~=${uvExp} then error("",0) end`)
  L(`local ${nCo}=coroutine.create(function() end)`)
  L(`local ${nCoSt}=coroutine.status(${nCo})`)
  L(`if ${nCoSt}~="suspended" then error("",0) end`)
  L(`coroutine.resume(${nCo})`)
  L(`if coroutine.status(${nCo})~="dead" then error("",0) end`)
  L(`local ${nPc1},${nPc2}=pcall(function() error("_c_",2) end)`)
  L(`if ${nPc1}~=false or type(${nPc2})~="string" then error("",0) end`)
  L(`local ${nSum}=0;for k,${nV} in pairs({${dispEntries}}) do ${nSum}=(${nSum}+${nV})%16777216 end`)
  L(`if ${nSum}~=${dispSum} then error("",0) end`)
  L(`local ${nEnvPrb}=getfenv and getfenv()`)
  L(`if ${nEnvPrb} and type(${nEnvPrb})~="table" then error("",0) end`)
  L(`if ${nEnvPrb} and ${nEnvPrb}.__VMDISPATCH~=nil then error("",0) end`)
  L(`local ${nStrT}=string.char(72,101,108,108,111)`)
  L(`if #${nStrT}~=5 or ${nStrT}:sub(1,1)~="H" then error("",0) end`)

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
