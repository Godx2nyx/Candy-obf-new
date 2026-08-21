import * as AST from "../ast/types"
import {
  Op, Instruction, Constant, Proto, UpvalDesc,
  createProto, makeInstr, makeInstrBx, makeInstrSBx,
  constNil, constBool, constNum, constStr
} from "./bytecode"

interface Local {
  name: string
  reg: number
  startPc: number
}

interface LoopInfo {
  breakPatches: number[]
  continuePatches: number[]
  type: "while" | "repeat" | "for" | "generic"
}

class FuncCompiler {
  proto: Proto
  locals: Local[] = []
  regTop: number = 0
  private scopeStack: number[] = []
  private loopStack: LoopInfo[] = []
  private parent: FuncCompiler | null
  private protoCounter: number

  constructor(
    id: number,
    params: number,
    hasVarArg: boolean,
    parent: FuncCompiler | null,
    protoCounter: number
  ) {
    this.proto = createProto(id, params, hasVarArg)
    this.parent = parent
    this.protoCounter = protoCounter
    this.regTop = params
    if (this.regTop > this.proto.maxStack) this.proto.maxStack = this.regTop
  }

  allocReg(): number {
    const r = this.regTop++
    if (this.regTop > this.proto.maxStack) this.proto.maxStack = this.regTop
    return r
  }

  freeReg() { this.regTop-- }

  reserveRegs(n: number): number {
    const base = this.regTop
    this.regTop += n
    if (this.regTop > this.proto.maxStack) this.proto.maxStack = this.regTop
    return base
  }

  freeRegs(n: number) { this.regTop -= n }

  addConst(c: Constant): number {
    const k = this.proto.constants
    for (let i = 0; i < k.length; i++) {
      const x = k[i]
      if (x.type !== c.type) continue
      if (c.type === "nil" && x.type === "nil") return i
      if (c.type === "boolean" && x.type === "boolean" && x.value === c.value) return i
      if (c.type === "number" && x.type === "number" && x.value === c.value) return i
      if (c.type === "string" && x.type === "string" && x.value === c.value) return i
    }
    k.push(c)
    return k.length - 1
  }

  emit(instr: Instruction): number {
    this.proto.instructions.push(instr)
    return this.proto.instructions.length - 1
  }

  emitABC(op: Op, a: number, b: number, c: number, line = 0): number {
    return this.emit(makeInstr(op, a, b, c, line))
  }

  emitABx(op: Op, a: number, bx: number, line = 0): number {
    return this.emit(makeInstrBx(op, a, bx, line))
  }

  emitASBx(op: Op, a: number, sbx: number, line = 0): number {
    return this.emit(makeInstrSBx(op, a, sbx, line))
  }

  currentPc(): number { return this.proto.instructions.length }

  patchJump(pc: number, target: number) {
    const offset = target - pc - 1
    this.proto.instructions[pc] = makeInstrSBx(
      this.proto.instructions[pc].op,
      this.proto.instructions[pc].a,
      offset
    )
  }

  pushScope() { this.scopeStack.push(this.locals.length) }

  popScope() {
    const base = this.scopeStack.pop()!
    const removed = this.locals.length - base
    for (let i = 0; i < removed; i++) this.locals.pop()
    this.regTop = this.locals.length > 0 ? this.locals[this.locals.length - 1].reg + 1 : this.proto.params
  }

  defineLocal(name: string): number {
    const reg = this.allocReg()
    this.locals.push({ name, reg, startPc: this.currentPc() })
    return reg
  }

  resolveLocal(name: string): number {
    for (let i = this.locals.length - 1; i >= 0; i--) {
      if (this.locals[i].name === name) return this.locals[i].reg
    }
    return -1
  }

  resolveUpval(name: string): number {
    for (let i = 0; i < this.proto.upvalues.length; i++) {
      if (this.proto.upvalues[i].name === name) return i
    }
    if (this.parent) {
      const localIdx = this.parent.resolveLocal(name)
      if (localIdx >= 0) {
        this.proto.upvalues.push({ name, inStack: true, idx: localIdx })
        return this.proto.upvalues.length - 1
      }
      const upvalIdx = this.parent.resolveUpval(name)
      if (upvalIdx >= 0) {
        this.proto.upvalues.push({ name, inStack: false, idx: upvalIdx })
        return this.proto.upvalues.length - 1
      }
    }
    return -1
  }

  pushLoop(type: LoopInfo["type"]): LoopInfo {
    const info: LoopInfo = { breakPatches: [], continuePatches: [], type }
    this.loopStack.push(info)
    return info
  }

  popLoop(): LoopInfo { return this.loopStack.pop()! }

  currentLoop(): LoopInfo | null {
    return this.loopStack.length > 0 ? this.loopStack[this.loopStack.length - 1] : null
  }

  nextProtoId(): number { return this.protoCounter++ }
}

export class Compiler {
  private protoCounter = 0

  compile(ast: AST.Block): Proto {
    const fc = new FuncCompiler(this.protoCounter++, 0, true, null, this.protoCounter)
    this.compileBlock(ast, fc)
    fc.emitABC(Op.RETURN, 0, 1, 0)
    return fc.proto
  }

  private compileBlock(block: AST.Block, fc: FuncCompiler) {
    fc.pushScope()
    for (const stmt of block.body) {
      this.compileStmt(stmt, fc)
    }
    fc.popScope()
  }

  private compileStmt(stmt: AST.Statement, fc: FuncCompiler) {
    switch (stmt.kind) {
      case "LocalStatement":      this.compileLocal(stmt, fc); break
      case "LocalFunction":       this.compileLocalFunc(stmt, fc); break
      case "FunctionDeclaration": this.compileFuncDecl(stmt, fc); break
      case "AssignStatement":     this.compileAssign(stmt, fc); break
      case "ExpressionStatement": this.compileExprStmt(stmt, fc); break
      case "DoStatement":         this.compileBlock(stmt.body, fc); break
      case "WhileStatement":      this.compileWhile(stmt, fc); break
      case "RepeatStatement":     this.compileRepeat(stmt, fc); break
      case "IfStatement":         this.compileIf(stmt, fc); break
      case "NumericFor":          this.compileNumFor(stmt, fc); break
      case "GenericFor":          this.compileGenFor(stmt, fc); break
      case "ReturnStatement":     this.compileReturn(stmt, fc); break
      case "BreakStatement":      this.compileBreak(fc); break
      case "ContinueStatement":   this.compileContinue(fc); break
    }
  }

  private compileLocal(stmt: AST.LocalStatement, fc: FuncCompiler) {
    const regs: number[] = []
    for (let i = 0; i < stmt.values.length; i++) {
      if (i < stmt.names.length) {
        const reg = this.compileExpr(stmt.values[i], fc, -1)
        regs.push(reg)
      }
    }
    for (let i = 0; i < stmt.names.length; i++) {
      if (i >= stmt.values.length) {
        const reg = fc.allocReg()
        fc.emitABC(Op.LOADNIL, reg, 0, 0)
        fc.defineLocal(stmt.names[i].name)
        regs.push(reg)
      } else {
        fc.locals.push({ name: stmt.names[i].name, reg: regs[i], startPc: fc.currentPc() })
      }
    }
  }

  private compileLocalFunc(stmt: AST.LocalFunction, fc: FuncCompiler) {
    const reg = fc.defineLocal(stmt.name.name)
    const childFc = this.createFuncCompiler(stmt.params, stmt.hasVarArg, fc)
    this.compileBlock(stmt.body, childFc)
    childFc.emitABC(Op.RETURN, 0, 1, 0)
    fc.proto.protos.push(childFc.proto)
    const protoIdx = fc.proto.protos.length - 1
    fc.emitABx(Op.CLOSURE, reg, protoIdx)
  }

  private compileFuncDecl(stmt: AST.FunctionDeclaration, fc: FuncCompiler) {
    const childFc = this.createFuncCompiler(stmt.params, stmt.hasVarArg, fc)
    this.compileBlock(stmt.body, childFc)
    childFc.emitABC(Op.RETURN, 0, 1, 0)
    fc.proto.protos.push(childFc.proto)
    const protoIdx = fc.proto.protos.length - 1
    const reg = fc.allocReg()
    fc.emitABx(Op.CLOSURE, reg, protoIdx)
    this.assignTo(stmt.name, reg, fc)
    fc.freeReg()
  }

  private createFuncCompiler(
    params: AST.Identifier[],
    hasVarArg: boolean,
    parent: FuncCompiler
  ): FuncCompiler {
    const fc = new FuncCompiler(
      this.protoCounter++,
      params.length,
      hasVarArg,
      parent,
      this.protoCounter
    )
    for (let i = 0; i < params.length; i++) {
      fc.locals.push({ name: params[i].name, reg: i, startPc: 0 })
    }
    return fc
  }

  private compileAssign(stmt: AST.AssignStatement, fc: FuncCompiler) {
    const regs: number[] = stmt.values.map(v => {
      const r = fc.allocReg()
      const res = this.compileExpr(v, fc, r)
      if (res !== r) fc.emitABC(Op.MOVE, r, res, 0)
      return r
    })
    for (let i = 0; i < stmt.targets.length; i++) {
      const reg = i < regs.length ? regs[i] : (() => {
        const r = fc.allocReg()
        fc.emitABC(Op.LOADNIL, r, 0, 0)
        return r
      })()
      this.assignTo(stmt.targets[i], reg, fc)
    }
    regs.forEach(() => fc.freeReg())
  }

  private assignTo(target: AST.Expression, reg: number, fc: FuncCompiler) {
    if (target.kind === "Identifier") {
      const local = fc.resolveLocal(target.name)
      if (local >= 0) {
        fc.emitABC(Op.MOVE, local, reg, 0)
      } else {
        const upval = fc.resolveUpval(target.name)
        if (upval >= 0) {
          fc.emitABC(Op.SETUPVAL, reg, upval, 0)
        } else {
          const k = fc.addConst(constStr(target.name))
          fc.emitABx(Op.SETGLOBAL, reg, k)
        }
      }
    } else if (target.kind === "FieldExpression") {
      const obj = this.compileExpr(target.object, fc, -1)
      const k = fc.addConst(constStr(target.field.name))
      fc.emitABC(Op.SETFIELD, obj, k, reg)
    } else if (target.kind === "IndexExpression") {
      const obj = this.compileExpr(target.object, fc, -1)
      const idx = this.compileExpr(target.index, fc, -1)
      fc.emitABC(Op.SETTABLE, obj, idx, reg)
    }
  }

  private compileExprStmt(stmt: AST.ExpressionStatement, fc: FuncCompiler) {
    const reg = fc.allocReg()
    this.compileExpr(stmt.expression, fc, reg)
    fc.freeReg()
  }

  private compileWhile(stmt: AST.WhileStatement, fc: FuncCompiler) {
    const loopStart = fc.currentPc()
    const condReg = fc.allocReg()
    this.compileExpr(stmt.condition, fc, condReg)
    const exitJmp = fc.emitASBx(Op.JMPNIF, condReg, 0)
    fc.freeReg()

    const loopInfo = fc.pushLoop("while")
    this.compileBlock(stmt.body, fc)
    fc.popLoop()

    const loopJmp = fc.emitASBx(Op.JMP, 0, 0)
    fc.patchJump(loopJmp, loopStart)
    const exitPc = fc.currentPc()
    fc.patchJump(exitJmp, exitPc)

    for (const p of loopInfo.breakPatches) fc.patchJump(p, exitPc)
    for (const p of loopInfo.continuePatches) fc.patchJump(p, loopStart)
  }

  private compileRepeat(stmt: AST.RepeatStatement, fc: FuncCompiler) {
    const loopStart = fc.currentPc()
    const loopInfo = fc.pushLoop("repeat")
    this.compileBlock(stmt.body, fc)
    fc.popLoop()

    const condReg = fc.allocReg()
    this.compileExpr(stmt.condition, fc, condReg)
    const loopJmp = fc.emitASBx(Op.JMPNIF, condReg, 0)
    fc.freeReg()
    fc.patchJump(loopJmp, loopStart)

    const exitPc = fc.currentPc()
    for (const p of loopInfo.breakPatches) fc.patchJump(p, exitPc)
  }

  private compileIf(stmt: AST.IfStatement, fc: FuncCompiler) {
    const endPatches: number[] = []

    for (let i = 0; i < stmt.clauses.length; i++) {
      const clause = stmt.clauses[i]
      let skipJmp = -1

      if (clause.condition !== null) {
        const condReg = fc.allocReg()
        this.compileExpr(clause.condition, fc, condReg)
        skipJmp = fc.emitASBx(Op.JMPNIF, condReg, 0)
        fc.freeReg()
      }

      this.compileBlock(clause.body, fc)

      if (i < stmt.clauses.length - 1) {
        endPatches.push(fc.emitASBx(Op.JMP, 0, 0))
      }

      if (skipJmp >= 0) fc.patchJump(skipJmp, fc.currentPc())
    }

    const endPc = fc.currentPc()
    for (const p of endPatches) fc.patchJump(p, endPc)
  }

  private compileNumFor(stmt: AST.NumericFor, fc: FuncCompiler) {
    const base = fc.reserveRegs(4)
    this.compileExprTo(stmt.start, fc, base)
    this.compileExprTo(stmt.limit, fc, base + 1)
    if (stmt.step) {
      this.compileExprTo(stmt.step, fc, base + 2)
    } else {
      fc.emitABx(Op.LOADINT, base + 2, fc.addConst(constNum(1)))
    }

    const prepPc = fc.emitASBx(Op.FORPREP, base, 0)
    const loopStart = fc.currentPc()

    fc.pushScope()
    fc.locals.push({ name: stmt.name.name, reg: base + 3, startPc: loopStart })
    const loopInfo = fc.pushLoop("for")
    this.compileBlock(stmt.body, fc)
    fc.popLoop()
    fc.popScope()

    const loopPc = fc.emitASBx(Op.FORLOOP, base, 0)
    fc.patchJump(loopPc, loopStart - 1)
    fc.patchJump(prepPc, fc.currentPc() - 1)

    const exitPc = fc.currentPc()
    for (const p of loopInfo.breakPatches) fc.patchJump(p, exitPc)

    fc.freeRegs(4)
  }

  private compileGenFor(stmt: AST.GenericFor, fc: FuncCompiler) {
    const base = fc.reserveRegs(3 + stmt.names.length)
    for (let i = 0; i < stmt.iterators.length && i < 3; i++) {
      this.compileExprTo(stmt.iterators[i], fc, base + i)
    }

    const loopStart = fc.currentPc()
    const callPc = fc.emitABC(Op.TFORLOOP, base, 0, stmt.names.length)

    fc.pushScope()
    for (let i = 0; i < stmt.names.length; i++) {
      fc.locals.push({ name: stmt.names[i].name, reg: base + 3 + i, startPc: loopStart })
    }
    const loopInfo = fc.pushLoop("generic")
    this.compileBlock(stmt.body, fc)
    fc.popLoop()
    fc.popScope()

    const jmpPc = fc.emitASBx(Op.JMP, 0, 0)
    fc.patchJump(jmpPc, loopStart)
    fc.patchJump(callPc, fc.currentPc())

    const exitPc = fc.currentPc()
    for (const p of loopInfo.breakPatches) fc.patchJump(p, exitPc)

    fc.freeRegs(3 + stmt.names.length)
  }

  private compileReturn(stmt: AST.ReturnStatement, fc: FuncCompiler) {
    if (stmt.values.length === 0) {
      fc.emitABC(Op.RETURN, 0, 1, 0)
      return
    }
    const base = fc.regTop
    for (const v of stmt.values) {
      const r = fc.allocReg()
      const res = this.compileExpr(v, fc, r)
      if (res !== r) fc.emitABC(Op.MOVE, r, res, 0)
    }
    fc.emitABC(Op.RETURN, base, stmt.values.length + 1, 0)
    fc.freeRegs(stmt.values.length)
  }

  private compileBreak(fc: FuncCompiler) {
    const loop = fc.currentLoop()
    if (!loop) return
    const p = fc.emitASBx(Op.JMP, 0, 0)
    loop.breakPatches.push(p)
  }

  private compileContinue(fc: FuncCompiler) {
    const loop = fc.currentLoop()
    if (!loop) return
    const p = fc.emitASBx(Op.JMP, 0, 0)
    loop.continuePatches.push(p)
  }

  private compileExprTo(expr: AST.Expression, fc: FuncCompiler, dst: number) {
    const res = this.compileExpr(expr, fc, dst)
    if (res !== dst) fc.emitABC(Op.MOVE, dst, res, 0)
  }

  private compileExpr(expr: AST.Expression, fc: FuncCompiler, dst: number): number {
    switch (expr.kind) {
      case "NilLiteral": {
        if (dst < 0) { const r = fc.allocReg(); fc.emitABC(Op.LOADNIL, r, 0, 0); return r }
        fc.emitABC(Op.LOADNIL, dst, 0, 0); return dst
      }

      case "BooleanLiteral": {
        const r = dst < 0 ? fc.allocReg() : dst
        fc.emitABC(Op.LOADBOOL, r, expr.value ? 1 : 0, 0); return r
      }

      case "NumberLiteral": {
        const r = dst < 0 ? fc.allocReg() : dst
        if (Number.isInteger(expr.value) && expr.value >= -0x8000 && expr.value < 0x8000) {
          fc.emitABx(Op.LOADINT, r, fc.addConst(constNum(expr.value)))
        } else {
          fc.emitABx(Op.LOADFLOAT, r, fc.addConst(constNum(expr.value)))
        }
        return r
      }

      case "StringLiteral": {
        const r = dst < 0 ? fc.allocReg() : dst
        fc.emitABx(Op.LOADSTR, r, fc.addConst(constStr(expr.value))); return r
      }

      case "VarArgLiteral": {
        const r = dst < 0 ? fc.allocReg() : dst
        fc.emitABC(Op.VARARG, r, 0, 0); return r
      }

      case "Identifier": {
        const local = fc.resolveLocal(expr.name)
        if (local >= 0) return local
        const upval = fc.resolveUpval(expr.name)
        if (upval >= 0) {
          const r = dst < 0 ? fc.allocReg() : dst
          fc.emitABC(Op.GETUPVAL, r, upval, 0); return r
        }
        const r = dst < 0 ? fc.allocReg() : dst
        fc.emitABx(Op.GETGLOBAL, r, fc.addConst(constStr(expr.name))); return r
      }

      case "BinaryExpression": {
        const r = dst < 0 ? fc.allocReg() : dst
        const l = this.compileExpr(expr.left, fc, -1)
        const ri = this.compileExpr(expr.right, fc, -1)
        const opMap: Record<string, Op> = {
          "+": Op.ADD, "-": Op.SUB, "*": Op.MUL, "/": Op.DIV,
          "%": Op.MOD, "^": Op.POW, "//": Op.IDIV,
          "&": Op.BAND, "|": Op.BOR, "~": Op.BXOR,
          "<<": Op.SHL, ">>": Op.SHR, "..": Op.CONCAT
        }
        const cmpMap: Record<string, Op> = {
          "==": Op.EQ, "~=": Op.NE, "<": Op.LT,
          "<=": Op.LE, ">": Op.GT, ">=": Op.GE
        }
        if (opMap[expr.operator]) {
          fc.emitABC(opMap[expr.operator], r, l, ri)
        } else if (cmpMap[expr.operator]) {
          fc.emitABC(cmpMap[expr.operator], r, l, ri)
        } else if (expr.operator === "and") {
          fc.emitABC(Op.MOVE, r, l, 0)
          const jmp = fc.emitASBx(Op.JMPNIF, r, 0)
          const rr = this.compileExpr(expr.right, fc, -1)
          fc.emitABC(Op.MOVE, r, rr, 0)
          fc.patchJump(jmp, fc.currentPc())
        } else if (expr.operator === "or") {
          fc.emitABC(Op.MOVE, r, l, 0)
          const jmp = fc.emitASBx(Op.JMPIF, r, 0)
          const rr = this.compileExpr(expr.right, fc, -1)
          fc.emitABC(Op.MOVE, r, rr, 0)
          fc.patchJump(jmp, fc.currentPc())
        }
        return r
      }

      case "UnaryExpression": {
        const r = dst < 0 ? fc.allocReg() : dst
        const operand = this.compileExpr(expr.operand, fc, -1)
        const opMap: Record<string, Op> = {
          "-": Op.UNM, "not": Op.NOT, "#": Op.LEN, "~": Op.BNOT
        }
        fc.emitABC(opMap[expr.operator] || Op.UNM, r, operand, 0)
        return r
      }

      case "FieldExpression": {
        const r = dst < 0 ? fc.allocReg() : dst
        const obj = this.compileExpr(expr.object, fc, -1)
        const k = fc.addConst(constStr(expr.field.name))
        fc.emitABC(Op.GETFIELD, r, obj, k); return r
      }

      case "IndexExpression": {
        const r = dst < 0 ? fc.allocReg() : dst
        const obj = this.compileExpr(expr.object, fc, -1)
        const idx = this.compileExpr(expr.index, fc, -1)
        fc.emitABC(Op.GETTABLE, r, obj, idx); return r
      }

      case "CallExpression": {
        const r = dst < 0 ? fc.allocReg() : dst
        const callee = this.compileExpr(expr.callee, fc, r)
        if (callee !== r) fc.emitABC(Op.MOVE, r, callee, 0)
        for (let i = 0; i < expr.args.length; i++) {
          const ar = fc.allocReg()
          this.compileExprTo(expr.args[i], fc, ar)
        }
        fc.emitABC(Op.CALL, r, expr.args.length + 1, 2)
        fc.freeRegs(expr.args.length)
        return r
      }

      case "MethodCallExpression": {
        const r = dst < 0 ? fc.allocReg() : dst
        const obj = this.compileExpr(expr.object, fc, r)
        if (obj !== r) fc.emitABC(Op.MOVE, r, obj, 0)
        const k = fc.addConst(constStr(expr.method.name))
        fc.emitABC(Op.SELF, r, r, k)
        for (let i = 0; i < expr.args.length; i++) {
          const ar = fc.allocReg()
          this.compileExprTo(expr.args[i], fc, ar)
        }
        fc.emitABC(Op.CALL, r, expr.args.length + 2, 2)
        fc.freeRegs(expr.args.length)
        return r
      }

      case "FunctionExpression": {
        const r = dst < 0 ? fc.allocReg() : dst
        const childFc = this.createFuncCompiler(expr.params, expr.hasVarArg, fc)
        this.compileBlock(expr.body, childFc)
        childFc.emitABC(Op.RETURN, 0, 1, 0)
        fc.proto.protos.push(childFc.proto)
        const protoIdx = fc.proto.protos.length - 1
        fc.emitABx(Op.CLOSURE, r, protoIdx); return r
      }

      case "TableConstructor": {
        const r = dst < 0 ? fc.allocReg() : dst
        fc.emitABC(Op.NEWTABLE, r, expr.fields.length, 0)
        let arrIdx = 1
        for (const field of expr.fields) {
          if (field.kind === "TableField") {
            const val = fc.allocReg()
            this.compileExprTo(field.value, fc, val)
            fc.emitABC(Op.LOADINT, val + 1, fc.addConst(constNum(arrIdx++)))
            fc.emitABC(Op.SETTABLE, r, val + 1, val)
            fc.freeReg(); fc.freeReg()
          } else if (field.kind === "TableKeyString") {
            const k = fc.addConst(constStr(field.key.name))
            const val = fc.allocReg()
            this.compileExprTo(field.value, fc, val)
            fc.emitABC(Op.SETFIELD, r, k, val)
            fc.freeReg()
          } else {
            const key = fc.allocReg()
            this.compileExprTo(field.key, fc, key)
            const val = fc.allocReg()
            this.compileExprTo(field.value, fc, val)
            fc.emitABC(Op.SETTABLE, r, key, val)
            fc.freeReg(); fc.freeReg()
          }
        }
        return r
      }

      default:
        return dst < 0 ? fc.allocReg() : dst
    }
  }
}

export function compile(ast: AST.Block): Proto {
  return new Compiler().compile(ast)
        }
