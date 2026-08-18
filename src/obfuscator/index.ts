import * as AST from "../ast/types"
import { Renamer, generateName } from "./rename"
import { StringEncryptor } from "./strings"
import { CodeGenerator } from "./codegen"

export interface ObfuscateOptions {
  rename: boolean
  encodeStrings: boolean
  minify: boolean
  seed?: number
}

export function obfuscate(ast: AST.Block, opts: ObfuscateOptions): string {
  const seed = opts.seed ?? (Math.random() * 0xFFFFFFFF) >>> 0

  let tree = ast

  if (opts.rename) {
    const renamer = new Renamer(seed)
    tree = renamer.rename(tree)
  }

  
  let decryptorCode = ""
  if (opts.encodeStrings) {
    const tableVar = generateName(999, seed ^ 0xDEAD)
    const decoderFn = generateName(998, seed ^ 0xBEEF)
    const encryptor = new StringEncryptor(seed, tableVar, decoderFn)
    tree = encryptor.transformAST(tree)
    decryptorCode = encryptor.generateDecryptorCode()
  }

  
  const codegen = new CodeGenerator({ minify: opts.minify })
  const mainCode = codegen.generate(tree)

  
  const parts: string[] = []
  if (decryptorCode) parts.push(decryptorCode)
  parts.push(mainCode)

  return parts.join("\n")
}

