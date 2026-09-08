import * as AST from "../ast/types"
import { Renamer, generateName } from "./rename"
import { StringEncryptor } from "./strings"
import { CodeGenerator } from "./codegen"
import { Compiler } from "../compiler/compiler"
import { generateRegVM } from "../vm/generator"

export interface ObfuscateOptions {
  rename: boolean
  encodeStrings: boolean
  minify: boolean
  vmType: "none" | "register"
  vmLevel: "normal" | "max" | "debug"
  seed?: number
}

export function obfuscate(ast: AST.Block, opts: ObfuscateOptions): string {
  const seed = opts.seed ?? ((Math.random() * 0xFFFFFFFF) >>> 0)

  let tree = ast

  if (opts.rename) {
    const renamer = new Renamer(seed)
    tree = renamer.rename(tree)
  }

  if (opts.vmType !== "none") {
    const compiler = new Compiler()
    const rawProto = compiler.compile(tree) as any

    // แปลงโครงสร้างข้อมูล (Normalize) ป้องกันค่า undefined เมื่อ VM Generator เรียกอ่าน .length
    const chunk = {
      ...rawProto,
      code: rawProto.code ?? rawProto.instructions ?? [],
      K: rawProto.K ?? rawProto.constants ?? rawProto.consts ?? [],
      p: rawProto.p ?? rawProto.protos ?? rawProto.prototypes ?? [],
      nInstructions: rawProto.nInstructions ?? (rawProto.code?.length || rawProto.instructions?.length || 0),
      maxRegs: rawProto.maxRegs ?? rawProto.maxstacksize ?? rawProto.maxStackSize ?? 0,
      numParams: rawProto.numParams ?? rawProto.numparams ?? 0,
      isVararg: rawProto.isVararg ?? rawProto.is_vararg ?? 0,
    }

    return generateRegVM(chunk as any, {
      polymorphicSeed: seed,
      level: opts.vmLevel
    })
  }

  let decryptorCode = ""

  if (opts.encodeStrings) {
    const tableVar = generateName(999, seed ^ 0xDEAD)
    const decoderFn = generateName(998, seed ^ 0xBEEF)

    const encryptor = new StringEncryptor(
      seed,
      tableVar,
      decoderFn
    )

    tree = encryptor.transformAST(tree)
    decryptorCode = encryptor.generateDecryptorCode()
  }

  const codegen = new CodeGenerator({
    minify: opts.minify
  })

  const mainCode = codegen.generate(tree)

  const parts: string[] = []

  if (decryptorCode) {
    parts.push(decryptorCode)
  }

  parts.push(mainCode)

  return parts.join("\n")
}
