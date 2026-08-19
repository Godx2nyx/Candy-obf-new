// ============================================================
// Candy-obf-new | VM Compiler
// AST (src/ast/Types.ts) -> LuauProto (src/vm/types.ts)
//
// This compiler is specifically matched to the current repo AST
// and the current register-based VM opcode set.
// ============================================================

import * as AST from "../ast/Types"
import { LuauProto, Instruction, UpvalDesc, LuauValue } from "./types"
import { Op } from "./opcodes"

const SBX_BIAS = 131071
const RK_BASE = 256

interface LocalVar {
  name: string
  reg: number
  depth: number
}

interface LoopState {
  type: "while" | "repeat" | "numeric" | "generic"
  breakJumps: number[]
  continueJumps: number[]
  continueTarget: number | null
}

class ProtoBuilder {
  readonly code: Instruction[] = []
  readonly constants: LuauValue[] = []
  readonly protos: LuauProto[] = []
  readonly upvals: UpvalDesc[] = []

  private readonly constantMap = new Map<string, number>()
  private readonly upvalMap = new Map<string, number>()
  private readonly locals: LocalVar[] = []

  private depth = 0
  private nextReg = 0

  maxStack = 0
  numParams = 0
  isVararg = false
  name?: string

  // ----------------------------------------------------------
  // Registers
  // ----------------------------------------------------------

  allocReg(): number {
    const r = this.nextReg++

    if (this.nextReg > this.maxStack) {
      this.maxStack = this.nextReg
    }

    return r
  }

  reserveRegs(count: number): number {
    const base = this.nextReg
    this.nextReg += count

    if (this.nextReg > this.maxStack) {
      this.maxStack = this.nextReg
    }

    return base
  }

  freeRegs(count: number): void {
    this.nextReg = Math.max(0, this.nextReg - count)
  }

  topReg(): number {
    return this.nextReg
  }

  // ----------------------------------------------------------
  // Constants
  // ----------------------------------------------------------

  addConst(value: LuauValue): number {
    const key =
      value === null
        ? "nil"
        : `${typeof value}:${JSON.stringify(value)}`

    const existing = this.constantMap.get(key)

    if (existing !== undefined) {
      return existing
    }

    const index = this.constants.length

    this.constants.push(value)
    this.constantMap.set(key, index)

    return index
  }

  rk(value: LuauValue): number {
    return RK_BASE + this.addConst(value)
  }

  // ----------------------------------------------------------
  // Scopes
  // ----------------------------------------------------------

  pushScope(): void {
    this.depth++
  }

  popScope(): void {
    while (
      this.locals.length > 0 &&
      this.locals[this.locals.length - 1].depth === this.depth
    ) {
      this.locals.pop()
    }

    this.depth--

    if (this.locals.length === 0) {
      this.nextReg = this.numParams
      return
    }

    const last = this.locals[this.locals.length - 1]
    this.nextReg = last.reg + 1
  }

  defineLocal(name: string, reg?: number): number {
    const r = reg === undefined ? this.allocReg() : reg

    this.locals.push({
      name,
      reg: r,
      depth: this.depth,
    })

    return r
  }

  resolveLocal(name: string): number | null {
    for (let i = this.locals.length - 1; i >= 0; i--) {
      if (this.locals[i].name === name) {
        return this.locals[i].reg
      }
    }

    return null
  }

  // ----------------------------------------------------------
  // Upvalues
  // ----------------------------------------------------------

  getUpvalue(name: string, parent: ProtoBuilder | null): number {
    const existing = this.upvalMap.get(name)

    if (existing !== undefined) {
      return existing
    }

    let descriptor: UpvalDesc

    if (parent) {
      const local = parent.resolveLocal(name)

      if (local !== null) {
        descriptor = {
          instack: true,
          idx: local,
          name,
        }
      } else {
        const parentUpval = parent.getExistingUpvalue(name)

        if (parentUpval !== null) {
          descriptor = {
            instack: false,
            idx: parentUpval,
            name,
          }
        } else {
          // Global/environment fallback.
          descriptor = {
            instack: false,
            idx: 0,
            name,
          }
        }
      }
    } else {
      descriptor = {
        instack: true,
        idx: 0,
        name,
      }
    }

    const index = this.upvals.length

    this.upvals.push(descriptor)
    this.upvalMap.set(name, index)

    return index
  }

  getExistingUpvalue(name: string): number | null {
    const index = this.upvalMap.get(name)
    return index === undefined ? null : index
  }

  // ----------------------------------------------------------
  // Instructions
  // ----------------------------------------------------------

  emit(
    op: Op,
    A: number,
    B: number,
    C: number
  ): number {
    const Bx = (B << 9) | C
    const sBx = Bx - SBX_BIAS

    this.code.push({
      op,
      A,
      B,
      C,
      Bx,
      sBx,
    })

    return this.code.length - 1
  }

  emitBx(
    op: Op,
    A: number,
    Bx: number
  ): number {
    const B = (Bx >> 9) & 0x1ff
    const C = Bx & 0x1ff

    return this.emit(op, A, B, C)
  }

  emitSBx(
    op: Op,
    A: number,
    sBx: number
  ): number {
    return this.emitBx(
      op,
      A,
      sBx + SBX_BIAS
    )
  }

  currentPc(): number {
    return this.code.length
  }

  patchJump(
    instruction: number,
    targetPc: number
  ): void {
    const sBx =
      targetPc -
      instruction -
      1

    this.code[instruction] = {
      ...this.code[instruction],
      ...this.makeSBx(sBx),
    }
  }

  private makeSBx(sBx: number) {
    const Bx = sBx + SBX_BIAS

    return {
      Bx,
      sBx,
      B: (Bx >> 9) & 0x1ff,
      C: Bx & 0x1ff,
    }
  }

  // ----------------------------------------------------------
  // Build
  // ----------------------------------------------------------

  build(): LuauProto {
    return {
      code: [...this.code],
      constants: [...this.constants],
      protos: [...this.protos],
      upvals: [...this.upvals],
      maxStackSize: this.maxStack,
      numParams: this.numParams,
      isVararg: this.isVararg,
      name: this.name,
    }
  }
}

// ============================================================
// Compiler
// ============================================================

export interface CompileOptions {
  name?: string
}

export class Compiler {
  private readonly options: CompileOptions

  private proto!: ProtoBuilder
  private parent: ProtoBuilder | null = null

  private loops: LoopState[] = []

  constructor(options: CompileOptions = {}) {
    this.options = options
  }

  // ----------------------------------------------------------
  // Entry
  // ----------------------------------------------------------

  compile(ast: AST.Block): LuauProto {
    this.proto = new ProtoBuilder()

    this.proto.name = this.options.name
    this.proto.numParams = 0
    this.proto.isVararg = true

    this.compileBlock(ast)

    // Implicit return.
    this.proto.emit(Op.RETURN, 0, 1, 0)

    return this.proto.build()
  }

  // ----------------------------------------------------------
  // Blocks
  // ----------------------------------------------------------

  private compileBlock(block: AST.Block): void {
    this.proto.pushScope()

    for (const statement of block.body) {
      this.compileStatement(statement)
    }

    this.proto.popScope()
  }

  // ----------------------------------------------------------
  // Statements
  // ----------------------------------------------------------

  private compileStatement(
    stmt: AST.Statement
  ): void {
    switch (stmt.kind) {
      case "LocalStatement":
        this.compileLocal(stmt)
        break

      case "LocalFunction":
        this.compileLocalFunction(stmt)
        break

      case "FunctionDeclaration":
        this.compileFunctionDeclaration(stmt)
        break

      case "AssignStatement":
        this.compileAssignment(stmt)
        break

      case "ExpressionStatement":
        this.compileExpressionStatement(stmt)
        break

      case "DoStatement":
        this.compileBlock(stmt.body)
        break

      case "WhileStatement":
        this.compileWhile(stmt)
        break

      case "RepeatStatement":
        this.compileRepeat(stmt)
        break

      case "IfStatement":
        this.compileIf(stmt)
        break

      case "NumericFor":
        this.compileNumericFor(stmt)
        break

      case "GenericFor":
        this.compileGenericFor(stmt)
        break

      case "ReturnStatement":
        this.compileReturn(stmt)
        break

      case "BreakStatement":
        this.compileBreak()
        break

      case "ContinueStatement":
        this.compileContinue()
        break
    }
  }

  // ----------------------------------------------------------
  // local a, b = ...
  // ----------------------------------------------------------

  private compileLocal(
    stmt: AST.LocalStatement
  ): void {
    const values: number[] = []

    // Evaluate RHS first.
    for (const expression of stmt.values) {
      const r = this.proto.allocReg()

      this.compileExpressionTo(
        expression,
        r
      )

      values.push(r)
    }

    // Define locals after RHS evaluation.
    for (let i = 0; i < stmt.names.length; i++) {
      const name = stmt.names[i].name

      const reg = this.proto.defineLocal(
        name
      )

      if (i < values.length) {
        if (reg !== values[i]) {
          this.proto.emit(
            Op.MOVE,
            reg,
            values[i],
            0
          )
        }
      } else {
        this.proto.emit(
          Op.LOADNIL,
          reg,
          reg,
          0
        )
      }
    }

    this.proto.freeRegs(values.length)
  }

  // ----------------------------------------------------------
  // local function foo(...)
  // ----------------------------------------------------------

  private compileLocalFunction(
    stmt: AST.LocalFunction
  ): void {
    const reg =
      this.proto.defineLocal(
        stmt.name.name
      )

    const child =
      this.compileFunction(
        stmt.params,
        stmt.hasVarArg,
        stmt.body
      )

    const protoIndex =
      this.proto.protos.length

    this.proto.protos.push(child)

    this.proto.emit(
      Op.CLOSURE,
      reg,
      (protoIndex >> 9) & 0x1ff,
      protoIndex & 0x1ff
    )
  }

  // ----------------------------------------------------------
  // function foo(...)
  // function obj.foo(...)
  // function obj:foo(...)
  // ----------------------------------------------------------

  private compileFunctionDeclaration(
    stmt: AST.FunctionDeclaration
  ): void {
    const temp = this.proto.allocReg()

    const child =
      this.compileFunction(
        stmt.params,
        stmt.hasVarArg,
        stmt.body
      )

    const protoIndex =
      this.proto.protos.length

    this.proto.protos.push(child)

    this.proto.emitBx(
      Op.CLOSURE,
      temp,
      protoIndex
    )

    this.assignTarget(
      stmt.name,
      temp
    )

    this.proto.freeRegs(1)
  }

  // ----------------------------------------------------------
  // a = b
  // ----------------------------------------------------------

  private compileAssignment(
    stmt: AST.AssignStatement
  ): void {
    const values: number[] = []

    // Evaluate every RHS before modifying LHS.
    for (const expression of stmt.values) {
      const r = this.proto.allocReg()

      this.compileExpressionTo(
        expression,
        r
      )

      values.push(r)
    }

    for (let i = 0; i < stmt.targets.length; i++) {
      let source: number

      if (i < values.length) {
        source = values[i]
      } else {
        source = this.proto.allocReg()

        this.proto.emit(
          Op.LOADNIL,
          source,
          source,
          0
        )
      }

      this.assignTarget(
        stmt.targets[i],
        source
      )
    }

    this.proto.freeRegs(values.length)
  }

  // ----------------------------------------------------------
  // expression statement
  // ----------------------------------------------------------

  private compileExpressionStatement(
    stmt: AST.ExpressionStatement
  ): void {
    const r = this.proto.allocReg()

    this.compileExpressionTo(
      stmt.expression,
      r
    )

    this.proto.freeRegs(1)
  }

  // ----------------------------------------------------------
  // while
  // ----------------------------------------------------------

  private compileWhile(
    stmt: AST.WhileStatement
  ): void {
    const loopStart =
      this.proto.currentPc()

    const loop: LoopState = {
      type: "while",
      breakJumps: [],
      continueJumps: [],
      continueTarget: loopStart,
    }

    this.loops.push(loop)

    const condition =
      this.proto.allocReg()

    this.compileExpressionTo(
      stmt.condition,
      condition
    )

    // TEST C=0:
    // truthy -> skip following JMP
    // false  -> execute following JMP
    this.proto.emit(
      Op.TEST,
      condition,
      0,
      0
    )

    const exit =
      this.proto.emitSBx(
        Op.JMP,
        0,
        0
      )

    this.proto.freeRegs(1)

    this.compileBlock(stmt.body)

    const back =
      this.proto.emitSBx(
        Op.JMP,
        0,
        0
      )

    this.proto.patchJump(
      back,
      loopStart
    )

    const exitPc =
      this.proto.currentPc()

    this.proto.patchJump(
      exit,
      exitPc
    )

    for (const jump of loop.breakJumps) {
      this.proto.patchJump(
        jump,
        exitPc
      )
    }

    for (const jump of loop.continueJumps) {
      this.proto.patchJump(
        jump,
        loop.continueTarget!
      )
    }

    this.loops.pop()
  }

  // ----------------------------------------------------------
  // repeat ... until
  // ----------------------------------------------------------

  private compileRepeat(
    stmt: AST.RepeatStatement
  ): void {
    const loopStart =
      this.proto.currentPc()

    const loop: LoopState = {
      type: "repeat",
      breakJumps: [],
      continueJumps: [],
      continueTarget: null,
    }

    this.loops.push(loop)

    this.compileBlock(stmt.body)

    const conditionPc =
      this.proto.currentPc()

    loop.continueTarget = conditionPc

    for (const jump of loop.continueJumps) {
      this.proto.patchJump(
        jump,
        conditionPc
      )
    }

    const condition =
      this.proto.allocReg()

    this.compileExpressionTo(
      stmt.condition,
      condition
    )

    // If true: TEST skips JMP.
    // If false: JMP loops back.
    this.proto.emit(
      Op.TEST,
      condition,
      0,
      0
    )

    const back =
      this.proto.emitSBx(
        Op.JMP,
        0,
        0
      )

    this.proto.patchJump(
      back,
      loopStart
    )

    this.proto.freeRegs(1)

    const exitPc =
      this.proto.currentPc()

    for (const jump of loop.breakJumps) {
      this.proto.patchJump(
        jump,
        exitPc
      )
    }

    this.loops.pop()
  }

  // ----------------------------------------------------------
  // if / elseif / else
  // ----------------------------------------------------------

  private compileIf(
    stmt: AST.IfStatement
  ): void {
    const endJumps: number[] = []

    for (let i = 0; i < stmt.clauses.length; i++) {
      const clause = stmt.clauses[i]

      if (clause.condition !== null) {
        const condition =
          this.proto.allocReg()

        this.compileExpressionTo(
          clause.condition,
          condition
        )

        this.proto.emit(
          Op.TEST,
          condition,
          0,
          0
        )

        const next =
          this.proto.emitSBx(
            Op.JMP,
            0,
            0
          )

        this.proto.freeRegs(1)

        this.compileBlock(
          clause.body
        )

        if (i < stmt.clauses.length - 1) {
          const end =
            this.proto.emitSBx(
              Op.JMP,
              0,
              0
            )

          endJumps.push(end)
        }

        this.proto.patchJump(
          next,
          this.proto.currentPc()
        )
      } else {
        this.compileBlock(
          clause.body
        )
      }
    }

    const endPc =
      this.proto.currentPc()

    for (const jump of endJumps) {
      this.proto.patchJump(
        jump,
        endPc
      )
    }
  }

  // ----------------------------------------------------------
  // numeric for
  // ----------------------------------------------------------

  private compileNumericFor(
    stmt: AST.NumericFor
  ): void {
    // A = initial
    // A+1 = limit
    // A+2 = step
    // A+3 = visible loop variable
    const base =
      this.proto.reserveRegs(4)

    this.compileExpressionTo(
      stmt.start,
      base
    )

    this.compileExpressionTo(
      stmt.limit,
      base + 1
    )

    if (stmt.step !== null) {
      this.compileExpressionTo(
        stmt.step,
        base + 2
      )
    } else {
      const one =
        this.proto.addConst(1)

      this.proto.emitBx(
        Op.LOADK,
        base + 2,
        one
      )
    }

    const prep =
      this.proto.emitSBx(
        Op.FORPREP,
        base,
        0
      )

    const loopStart =
      this.proto.currentPc()

    const loop: LoopState = {
      type: "numeric",
      breakJumps: [],
      continueJumps: [],
      continueTarget: null,
    }

    this.loops.push(loop)

    this.proto.pushScope()

    this.proto.defineLocal(
      stmt.name.name,
      base + 3
    )

    this.compileBlock(
      stmt.body
    )

    this.proto.popScope()

    const forLoop =
      this.proto.emitSBx(
        Op.FORLOOP,
        base,
        0
      )

    const continueTarget =
      forLoop

    loop.continueTarget =
      continueTarget

    for (const jump of loop.continueJumps) {
      this.proto.patchJump(
        jump,
        continueTarget
      )
    }

    this.proto.patchJump(
      forLoop,
      loopStart
    )

    this.proto.patchJump(
      prep,
      loopStart
    )

    const exitPc =
      this.proto.currentPc()

    for (const jump of loop.breakJumps) {
      this.proto.patchJump(
        jump,
        exitPc
      )
    }

    this.loops.pop()

    this.proto.freeRegs(4)
  }

  // ----------------------------------------------------------
  // generic for
  // ----------------------------------------------------------

  private compileGenericFor(
    stmt: AST.GenericFor
  ): void {
    // A     = iterator function
    // A + 1 = state
    // A + 2 = control variable
    // A + 3... = loop variables
    const base =
      this.proto.reserveRegs(
        3 + stmt.names.length
      )

    for (
      let i = 0;
      i < stmt.iterators.length && i < 3;
      i++
    ) {
      this.compileExpressionTo(
        stmt.iterators[i],
        base + i
      )
    }

    const loopStart =
      this.proto.currentPc()

    const loop: LoopState = {
      type: "generic",
      breakJumps: [],
      continueJumps: [],
      continueTarget: null,
    }

    this.loops.push(loop)

    this.proto.emit(
      Op.TFORCALL,
      base,
      0,
      stmt.names.length
    )

    const loopTest =
      this.proto.emitSBx(
        Op.TFORLOOP,
        base,
        0
      )

    this.proto.pushScope()

    for (let i = 0; i < stmt.names.length; i++) {
      this.proto.defineLocal(
        stmt.names[i].name,
        base + 3 + i
      )
    }

    this.compileBlock(
      stmt.body
    )

    this.proto.popScope()

    loop.continueTarget =
      loopStart

    for (const jump of loop.continueJumps) {
      this.proto.patchJump(
        jump,
        loopStart
      )
    }

    const back =
      this.proto.emitSBx(
        Op.JMP,
        0,
        0
      )

    this.proto.patchJump(
      back,
      loopStart
    )

    // TFORLOOP jumps here when iteration ends.
    this.proto.patchJump(
      loopTest,
      this.proto.currentPc()
    )

    const exitPc =
      this.proto.currentPc()

    for (const jump of loop.breakJumps) {
      this.proto.patchJump(
        jump,
        exitPc
      )
    }

    this.loops.pop()

    this.proto.freeRegs(
      3 + stmt.names.length
    )
  }

  // ----------------------------------------------------------
  // return
  // ----------------------------------------------------------

  private compileReturn(
    stmt: AST.ReturnStatement
  ): void {
    if (stmt.values.length === 0) {
      this.proto.emit(
        Op.RETURN,
        0,
        1,
        0
      )

      return
    }

    const base =
      this.proto.topReg()

    for (const expression of stmt.values) {
      const r =
        this.proto.allocReg()

      this.compileExpressionTo(
        expression,
        r
      )
    }

    this.proto.emit(
      Op.RETURN,
      base,
      stmt.values.length + 1,
      0
    )

    this.proto.freeRegs(
      stmt.values.length
    )
  }

  // ----------------------------------------------------------
  // break
  // ----------------------------------------------------------

  private compileBreak(): void {
    const loop =
      this.loops[this.loops.length - 1]

    if (!loop) {
      return
    }

    const jump =
      this.proto.emitSBx(
        Op.JMP,
        0,
        0
      )

    loop.breakJumps.push(jump)
  }

  // ----------------------------------------------------------
  // continue
  // ----------------------------------------------------------

  private compileContinue(): void {
    const loop =
      this.loops[this.loops.length - 1]

    if (!loop) {
      return
    }

    const jump =
      this.proto.emitSBx(
        Op.JMP,
        0,
        0
      )

    loop.continueJumps.push(jump)

    if (loop.continueTarget !== null) {
      this.proto.patchJump(
        jump,
        loop.continueTarget
      )
    }
  }

  // ==========================================================
  // Expressions
  // ==========================================================

  private compileExpressionTo(
    expression: AST.Expression,
    dst: number
  ): void {
    const result =
      this.compileExpression(
        expression,
        dst
      )

    if (result !== dst) {
      this.proto.emit(
        Op.MOVE,
        dst,
        result,
        0
      )
    }
  }

  private compileExpression(
    expression: AST.Expression,
    dst: number
  ): number {
    switch (expression.kind) {
      case "NilLiteral":
        this.proto.emit(
          Op.LOADNIL,
          dst,
          dst,
          0
        )
        return dst

      case "BooleanLiteral":
        this.proto.emit(
          Op.LOADBOOL,
          dst,
          expression.value ? 1 : 0,
          0
        )
        return dst

      case "NumberLiteral": {
        const k =
          this.proto.addConst(
            expression.value
          )

        this.proto.emitBx(
          Op.LOADK,
          dst,
          k
        )

        return dst
      }

      case "StringLiteral": {
        const k =
          this.proto.addConst(
            expression.value
          )

        this.proto.emitBx(
          Op.LOADK,
          dst,
          k
        )

        return dst
      }

      case "VarArgLiteral":
        this.proto.emit(
          Op.VARARG,
          dst,
          2,
          0
        )
        return dst

      case "Identifier":
        return this.compileIdentifier(
          expression,
          dst
        )

      case "BinaryExpression":
        return this.compileBinary(
          expression,
          dst
        )

      case "UnaryExpression":
        return this.compileUnary(
          expression,
          dst
        )

      case "FieldExpression":
        return this.compileField(
          expression,
          dst
        )

      case "IndexExpression":
        return this.compileIndex(
          expression,
          dst
        )

      case "CallExpression":
        return this.compileCall(
          expression,
          dst
        )

      case "MethodCallExpression":
        return this.compileMethodCall(
          expression,
          dst
        )

      case "FunctionExpression":
        return this.compileFunctionExpression(
          expression,
          dst
        )

      case "TableConstructor":
        return this.compileTable(
          expression,
          dst
        )
    }
  }

  // ----------------------------------------------------------
  // Identifier
  // ----------------------------------------------------------

  private compileIdentifier(
    expression: AST.Identifier,
    dst: number
  ): number {
    const local =
      this.proto.resolveLocal(
        expression.name
      )

    if (local !== null) {
      if (local !== dst) {
        this.proto.emit(
          Op.MOVE,
          dst,
          local,
          0
        )
      }

      return dst
    }

    const upval =
      this.proto.getExistingUpvalue(
        expression.name
      )

    if (upval !== null) {
      this.proto.emit(
        Op.GETUPVAL,
        dst,
        upval,
        0
      )

      return dst
    }

    const global =
      this.proto.addConst(
        expression.name
      )

    this.proto.emitBx(
      Op.GETGLOBAL,
      dst,
      global
    )

    return dst
  }

  // ----------------------------------------------------------
  // Binary
  // ----------------------------------------------------------

  private compileBinary(
    expression: AST.BinaryExpression,
    dst: number
  ): number {
    const op =
      expression.operator

    // Short-circuit AND.
    if (op === "and") {
      this.compileExpressionTo(
        expression.left,
        dst
      )

      // If truthy: skip JMP.
      // If false: execute JMP to end.
      this.proto.emit(
        Op.TEST,
        dst,
        0,
        0
      )

      const end =
        this.proto.emitSBx(
          Op.JMP,
          0,
          0
        )

      this.compileExpressionTo(
        expression.right,
        dst
      )

      this.proto.patchJump(
        end,
        this.proto.currentPc()
      )

      return dst
    }

    // Short-circuit OR.
    if (op === "or") {
      this.compileExpressionTo(
        expression.left,
        dst
      )

      // If false: skip JMP.
      // If true: execute JMP to end.
      this.proto.emit(
        Op.TEST,
        dst,
        0,
        1
      )

      const end =
        this.proto.emitSBx(
          Op.JMP,
          0,
          0
        )

      this.compileExpressionTo(
        expression.right,
        dst
      )

      this.proto.patchJump(
        end,
        this.proto.currentPc()
      )

      return dst
    }

    const left =
      this.proto.allocReg()

    const right =
      this.proto.allocReg()

    this.compileExpressionTo(
      expression.left,
      left
    )

    this.compileExpressionTo(
      expression.right,
      right
    )

    const arithmetic: Partial<Record<string, Op>> = {
      "+": Op.ADD,
      "-": Op.SUB,
      "*": Op.MUL,
      "/": Op.DIV,
      "%": Op.MOD,
      "^": Op.POW,
      "//": Op.IDIV,
      "&": Op.BAND,
      "|": Op.BOR,
      "~": Op.BXOR,
      "<<": Op.SHL,
      ">>": Op.SHR,
      "..": Op.CONCAT,
    }

    const arithmeticOp =
      arithmetic[op]

    if (arithmeticOp !== undefined) {
      this.proto.emit(
        arithmeticOp,
        dst,
        left,
        right
      )

      this.proto.freeRegs(2)

      return dst
    }

    // Comparisons.
    if (
      op === "==" ||
      op === "~=" ||
      op === "<" ||
      op === "<=" ||
      op === ">" ||
      op === ">="
    ) {
      this.emitComparison(
        op,
        left,
        right,
        dst
      )

      this.proto.freeRegs(2)

      return dst
    }

    // Unknown operator: produce nil rather than invalid bytecode.
    this.proto.emit(
      Op.LOADNIL,
      dst,
      dst,
      0
    )

    this.proto.freeRegs(2)

    return dst
  }

  // ----------------------------------------------------------
  // Comparison -> boolean
  // ----------------------------------------------------------

  private emitComparison(
    operator: string,
    left: number,
    right: number,
    dst: number
  ): void {
    let op: Op
    let b = left
    let c = right

    switch (operator) {
      case "==":
        op = Op.EQ
        break

      case "~=":
        op = Op.EQ
        break

      case "<":
        op = Op.LT
        break

      case "<=":
        op = Op.LE
        break

      case ">":
        op = Op.LT
        b = right
        c = left
        break

      case ">=":
        op = Op.LE
        b = right
        c = left
        break

      default:
        this.proto.emit(
          Op.LOADBOOL,
          dst,
          0,
          0
        )
        return
    }

    // A=1 means:
    // condition true  -> execute next instruction
    // condition false -> skip next instruction
    //
    // A=0 reverses that.
    const polarity =
      operator === "~=" ? 0 : 1

    this.proto.emit(
      op,
      polarity,
      b,
      c
    )

    // True path.
    this.proto.emit(
      Op.LOADBOOL,
      dst,
      1,
      1
    )

    // False path.
    this.proto.emit(
      Op.LOADBOOL,
      dst,
      0,
      0
    )
  }

  // ----------------------------------------------------------
  // Unary
  // ----------------------------------------------------------

  private compileUnary(
    expression: AST.UnaryExpression,
    dst: number
  ): number {
    const operand =
      this.proto.allocReg()

    this.compileExpressionTo(
      expression.operand,
      operand
    )

    switch (expression.operator) {
      case "-":
        this.proto.emit(
          Op.UNM,
          dst,
          operand,
          0
        )
        break

      case "not":
        this.proto.emit(
          Op.NOT,
          dst,
          operand,
          0
        )
        break

      case "#":
        this.proto.emit(
          Op.LEN,
          dst,
          operand,
          0
        )
        break

      case "~":
        this.proto.emit(
          Op.BNOT,
          dst,
          operand,
          0
        )
        break

      default:
        this.proto.emit(
          Op.LOADNIL,
          dst,
          dst,
          0
        )
    }

    this.proto.freeRegs(1)

    return dst
  }

  // ----------------------------------------------------------
  // obj.field
  // ----------------------------------------------------------

  private compileField(
    expression: AST.FieldExpression,
    dst: number
  ): number {
    const object =
      this.proto.allocReg()

    this.compileExpressionTo(
      expression.object,
      object
    )

    const key =
      this.proto.rk(
        expression.field.name
      )

    this.proto.emit(
      Op.GETTABLE,
      dst,
      object,
      key
    )

    this.proto.freeRegs(1)

    return dst
  }

  // ----------------------------------------------------------
  // obj[index]
  // ----------------------------------------------------------

  private compileIndex(
    expression: AST.IndexExpression,
    dst: number
  ): number {
    const object =
      this.proto.allocReg()

    const index =
      this.proto.allocReg()

    this.compileExpressionTo(
      expression.object,
      object
    )

    this.compileExpressionTo(
      expression.index,
      index
    )

    this.proto.emit(
      Op.GETTABLE,
      dst,
      object,
      index
    )

    this.proto.freeRegs(2)

    return dst
  }

  // ----------------------------------------------------------
  // foo(...)
  // ----------------------------------------------------------

  private compileCall(
    expression: AST.CallExpression,
    dst: number
  ): number {
    const base =
      this.proto.reserveRegs(
        expression.args.length + 1
      )

    this.compileExpressionTo(
      expression.callee,
      base
    )

    for (
      let i = 0;
      i < expression.args.length;
      i++
    ) {
      this.compileExpressionTo(
        expression.args[i],
        base + 1 + i
      )
    }

    // B = number of arguments + function.
    // C = 2 => one return value.
    this.proto.emit(
      Op.CALL,
      base,
      expression.args.length + 1,
      2
    )

    if (dst !== base) {
      this.proto.emit(
        Op.MOVE,
        dst,
        base,
        0
      )
    }

    this.proto.freeRegs(
      expression.args.length + 1
    )

    return dst
  }

  // ----------------------------------------------------------
  // obj:method(...)
  // ----------------------------------------------------------

  private compileMethodCall(
    expression: AST.MethodCallExpression,
    dst: number
  ): number {
    const base =
      this.proto.reserveRegs(
        expression.args.length + 2
      )

    this.compileExpressionTo(
      expression.object,
      base
    )

    const key =
      this.proto.rk(
        expression.method.name
      )

    // SELF:
    // R(A+1) = object
    // R(A)   = object[method]
    this.proto.emit(
      Op.SELF,
      base,
      base,
      key
    )

    for (
      let i = 0;
      i < expression.args.length;
      i++
    ) {
      this.compileExpressionTo(
        expression.args[i],
        base + 2 + i
      )
    }

    // Function + self + explicit arguments.
    this.proto.emit(
      Op.CALL,
      base,
      expression.args.length + 2,
      2
    )

    if (dst !== base) {
      this.proto.emit(
        Op.MOVE,
        dst,
        base,
        0
      )
    }

    this.proto.freeRegs(
      expression.args.length + 2
    )

    return dst
  }

  // ----------------------------------------------------------
  // function(...) ... end
  // ----------------------------------------------------------

  private compileFunctionExpression(
    expression: AST.FunctionExpression,
    dst: number
  ): number {
    const child =
      this.compileFunction(
        expression.params,
        expression.hasVarArg,
        expression.body
      )

    const protoIndex =
      this.proto.protos.length

    this.proto.protos.push(child)

    this.proto.emitBx(
      Op.CLOSURE,
      dst,
      protoIndex
    )

    return dst
  }

  // ----------------------------------------------------------
  // function compiler
  // ----------------------------------------------------------

  private compileFunction(
    params: AST.Identifier[],
    hasVarArg: boolean,
    body: AST.Block
  ): LuauProto {
    const parentProto = this.proto

    const child =
      new ProtoBuilder()

    child.numParams =
      params.length

    child.isVararg =
      hasVarArg

    // Parameters occupy R0..Rn.
    for (
      let i = 0;
      i < params.length;
      i++
    ) {
      child.defineLocal(
        params[i].name,
        i
      )
    }

    // The generated VM passes the parent upvalue
    // array to nested closures.
    //
    // Keep _ENV at index 0 when the function needs
    // an environment reference.
    child.upvals.push({
      instack: false,
      idx: 0,
      name: "_ENV",
    })

    const savedProto =
      this.proto

    const savedParent =
      this.parent

    this.proto = child
    this.parent = parentProto

    this.compileBlock(body)

    this.proto.emit(
      Op.RETURN,
      0,
      1,
      0
    )

    this.proto =
      savedProto

    this.parent =
      savedParent

    return child.build()
  }

  // ----------------------------------------------------------
  // Assignment target
  // ----------------------------------------------------------

  private assignTarget(
    target: AST.Expression,
    source: number
  ): void {
    switch (target.kind) {
      case "Identifier": {
        const local =
          this.proto.resolveLocal(
            target.name
          )

        if (local !== null) {
          if (local !== source) {
            this.proto.emit(
              Op.MOVE,
              local,
              source,
              0
            )
          }

          return
        }

        const upval =
          this.proto.getExistingUpvalue(
            target.name
          )

        if (upval !== null) {
          this.proto.emit(
            Op.SETUPVAL,
            source,
            upval,
            0
          )

          return
        }

        const global =
          this.proto.addConst(
            target.name
          )

        this.proto.emitBx(
          Op.SETGLOBAL,
          source,
          global
        )

        return
      }

      case "FieldExpression": {
        const object =
          this.proto.allocReg()

        this.compileExpressionTo(
          target.object,
          object
        )

        const key =
          this.proto.rk(
            target.field.name
          )

        this.proto.emit(
          Op.SETTABLE,
          object,
          key,
          source
        )

        this.proto.freeRegs(1)
        return
      }

      case "IndexExpression": {
        const object =
          this.proto.allocReg()

        const index =
          this.proto.allocReg()

        this.compileExpressionTo(
          target.object,
          object
        )

        this.compileExpressionTo(
          target.index,
          index
        )

        this.proto.emit(
          Op.SETTABLE,
          object,
          index,
          source
        )

        this.proto.freeRegs(2)
        return
      }
    }
  }

  // ----------------------------------------------------------
  // table constructor
  // ----------------------------------------------------------

  private compileTable(
    expression: AST.TableConstructor,
    dst: number
  ): number {
    this.proto.emit(
      Op.NEWTABLE,
      dst,
      0,
      0
    )

    let arrayIndex = 1

    for (const field of expression.fields) {
      const value =
        this.proto.allocReg()

      this.compileExpressionTo(
        field.value,
        value
      )

      if (field.kind === "TableField") {
        const key =
          this.proto.rk(
            arrayIndex++
          )

        this.proto.emit(
          Op.SETTABLE,
          dst,
          key,
          value
        )
      } else if (
        field.kind === "TableKeyString"
      ) {
        const key =
          this.proto.rk(
            field.key.name
          )

        this.proto.emit(
          Op.SETTABLE,
          dst,
          key,
          value
        )
      } else {
        const key =
          this.proto.allocReg()

        this.compileExpressionTo(
          field.key,
          key
        )

        this.proto.emit(
          Op.SETTABLE,
          dst,
          key,
          value
        )

        this.proto.freeRegs(1)
      }

      this.proto.freeRegs(1)
    }

    return dst
  }
}

// ============================================================
// Convenience API
// ============================================================

export function compile(
  ast: AST.Block,
  options?: CompileOptions
): LuauProto {
  return new Compiler(options).compile(ast)
  }
