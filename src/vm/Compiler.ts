// ============================================================
//  Candy-obf-new  |  Compiler (AST → LuauProto bytecode)
//
//  Connect this to YOUR existing parser/AST.
//  The interfaces below are generic — adapt to match
//  the AST node shapes from your `src/ast/` folder.
//
//  Quick integration steps:
//  1. Import your AST types instead of the stubs below.
//  2. Fill in each visitor method to emit instructions.
//  3. Call:
//       const proto  = compile(ast, { name: "main" });
//       const config = makeConfig();
//       const luau   = generateVM(proto, config);
// ============================================================

import { LuauProto, Instruction, UpvalDesc, LuauValue } from "./types";
import { Op } from "./opcodes";

// ── Generic AST stubs (replace with your own imports) ────────
export interface ASTNode { type: string }

export interface Block       extends ASTNode { body: Statement[] }
export interface Statement   extends ASTNode {}
export interface Expression  extends ASTNode {}

// Statements
export interface AssignStmt  extends Statement { targets: Expression[]; values: Expression[] }
export interface LocalStmt   extends Statement { names: string[]; values: Expression[] }
export interface DoStmt      extends Statement { body: Block }
export interface WhileStmt   extends Statement { condition: Expression; body: Block }
export interface RepeatStmt  extends Statement { body: Block; condition: Expression }
export interface IfStmt      extends Statement { condition: Expression; consequent: Block; alternate?: Block | IfStmt }
export interface NumericFor  extends Statement { name: string; start: Expression; limit: Expression; step?: Expression; body: Block }
export interface GenericFor  extends Statement { names: string[]; iterators: Expression[]; body: Block }
export interface FunctionStmt extends Statement { name: Expression; func: FuncExpr }
export interface LocalFuncStmt extends Statement { name: string; func: FuncExpr }
export interface ReturnStmt  extends Statement { values: Expression[] }
export interface BreakStmt   extends Statement {}
export interface ContinueStmt extends Statement {}
export interface ExprStmt    extends Statement { expression: Expression }

// Expressions
export interface NilExpr      extends Expression {}
export interface TrueExpr     extends Expression {}
export interface FalseExpr    extends Expression {}
export interface NumberExpr   extends Expression { value: number }
export interface StringExpr   extends Expression { value: string }
export interface VarArgExpr   extends Expression {}
export interface NameExpr     extends Expression { name: string }
export interface IndexExpr    extends Expression { object: Expression; index: Expression }
export interface FieldExpr    extends Expression { object: Expression; field: string }
export interface MethodExpr   extends Expression { object: Expression; method: string; args: Expression[] }
export interface CallExpr     extends Expression { callee: Expression; args: Expression[] }
export interface BinopExpr    extends Expression { op: string; left: Expression; right: Expression }
export interface UnopExpr     extends Expression { op: string; operand: Expression }
export interface FuncExpr     extends Expression { params: string[]; isVararg: boolean; body: Block }
export interface TableExpr    extends Expression { fields: TableField[] }

export interface TableField   extends ASTNode {
  key?: Expression;    // undefined = array-style
  value: Expression;
}

// ── Compile options ──────────────────────────────────────────
export interface CompileOptions {
  name?:        string;
  optimise?:    boolean;   // dead-code folding, const-fold
  stripDebug?:  boolean;   // drop lineInfo
}

// ── Scope / variable resolution ──────────────────────────────
interface LocalVar {
  name:     string;
  reg:      number;
  depth:    number;
  captured: boolean;
}

interface UpvalRef {
  name:    string;
  instack: boolean;
  idx:     number;
}

// ── Compiler state (per-prototype) ──────────────────────────
class ProtoBuilder {
  code:         Instruction[]  = [];
  constants:    LuauValue[]    = [];
  constMap:     Map<string, number> = new Map();   // serialised key → index
  protos:       LuauProto[]    = [];
  upvals:       UpvalDesc[]    = [];
  upvalMap:     Map<string, number> = new Map();
  maxStack      = 0;
  numParams     = 0;
  isVararg      = false;
  name?:        string;

  private locals: LocalVar[]   = [];
  private depth                = 0;
  private nextReg              = 0;
  private pendingJumps: { [label: string]: number[] } = {};
  private labels:       { [label: string]: number }   = {};

  // ── Register allocation ─────────────────────────────────
  allocReg(): number {
    const r = this.nextReg++;
    if (r + 1 > this.maxStack) this.maxStack = r + 1;
    return r;
  }
  freeReg(n = 1) { this.nextReg -= n; }
  topReg() { return this.nextReg; }

  // ── Constant pool ────────────────────────────────────────
  addConst(v: LuauValue): number {
    const key = JSON.stringify(v);
    if (this.constMap.has(key)) return this.constMap.get(key)!;
    const idx = this.constants.length;
    this.constants.push(v);
    this.constMap.set(key, idx);
    return idx;
  }

  // RK encoding: constants ≥ 256 → return 256+idx
  constRK(v: LuauValue): number { return 256 + this.addConst(v); }

  // ── Local variable table ─────────────────────────────────
  pushScope() { this.depth++; }
  popScope(): number[] {
    const closed: number[] = [];
    let i = this.locals.length - 1;
    while (i >= 0 && this.locals[i].depth === this.depth) {
      if (this.locals[i].captured) closed.push(this.locals[i].reg);
      this.locals.pop();
      i--;
    }
    this.depth--;
    return closed;
  }

  addLocal(name: string): number {
    const reg = this.allocReg();
    this.locals.push({ name, reg, depth: this.depth, captured: false });
    return reg;
  }

  resolveLocal(name: string): number | null {
    for (let i = this.locals.length - 1; i >= 0; i--) {
      if (this.locals[i].name === name) return this.locals[i].reg;
    }
    return null;
  }

  markCaptured(name: string) {
    for (let i = this.locals.length - 1; i >= 0; i--) {
      if (this.locals[i].name === name) { this.locals[i].captured = true; break; }
    }
  }

  // ── Instruction emission ─────────────────────────────────
  emit(op: Op, A: number, B: number, C: number): number {
    const Bx  = (B << 9) | C;
    const sBx = Bx - 131071;
    this.code.push({ op, A, B, C, Bx, sBx });
    return this.code.length - 1;   // instruction index
  }

  emitBx(op: Op, A: number, Bx: number): number {
    const B = (Bx >> 9) & 0x1FF;
    const C =  Bx       & 0x1FF;
    return this.emit(op, A, B, C);
  }

  emitsBx(op: Op, A: number, sBx: number): number {
    return this.emitBx(op, A, sBx + 131071);
  }

  // Patch a JMP target
  patchJump(instrIdx: number, targetPc: number) {
    const sBx = targetPc - instrIdx - 1;
    this.code[instrIdx] = { ...this.code[instrIdx],
      ...this.makesBxFields(sBx) };
  }
  private makesBxFields(sBx: number) {
    const Bx = sBx + 131071;
    return { Bx, sBx, B: (Bx >> 9) & 0x1FF, C: Bx & 0x1FF };
  }

  currentPc() { return this.code.length; }

  // ── Build final proto ────────────────────────────────────
  build(): LuauProto {
    return {
      code:         this.code,
      constants:    this.constants,
      protos:       this.protos,
      upvals:       this.upvals,
      maxStackSize: this.maxStack,
      numParams:    this.numParams,
      isVararg:     this.isVararg,
      name:         this.name,
    };
  }
}

// ── Main compiler ────────────────────────────────────────────
export class Compiler {
  private opts: CompileOptions;
  private proto!: ProtoBuilder;

  constructor(opts: CompileOptions = {}) {
    this.opts = opts;
  }

  // ── Entry point ─────────────────────────────────────────
  compile(block: Block): LuauProto {
    this.proto = new ProtoBuilder();
    this.proto.name    = this.opts.name;
    this.proto.isVararg = true;   // top-level is always vararg

    // Top-level _ENV upvalue
    this.proto.upvals.push({ instack: true, idx: 0, name: "_ENV" });
    this.proto.upvalMap.set("_ENV", 0);

    this.compileBlock(block);
    this.proto.emit(Op.RETURN, 0, 1, 0);   // implicit return
    return this.proto.build();
  }

  // ── Block compilation ────────────────────────────────────
  private compileBlock(block: Block) {
    this.proto.pushScope();
    for (const stmt of block.body) this.compileStmt(stmt);
    const closed = this.proto.popScope();
    if (closed.length > 0) {
      this.proto.emit(Op.CLOSE, Math.min(...closed), 0, 0);
    }
  }

  // ── Statement dispatch ───────────────────────────────────
  private compileStmt(node: Statement) {
    const p = this.proto;

    switch (node.type) {
      // ── Local variable declaration ───────────────────────
      case "LocalStatement": {
        const s = node as LocalStmt;
        const regs: number[] = [];
        const valCount = s.values.length;

        for (let i = 0; i < s.names.length; i++) {
          const reg = p.allocReg();
          regs.push(reg);
          if (i < valCount) {
            this.compileExprToReg(s.values[i], reg);
          } else {
            p.emit(Op.LOADNIL, reg, reg, 0);
          }
        }

        // Register locals after all RHS evaluated (multi-assign safety)
        for (let i = 0; i < s.names.length; i++) {
          p.locals.push({ name: s.names[i], reg: regs[i],
                          depth: (p as any).depth, captured: false });
        }
        break;
      }

      // ── Assignment ───────────────────────────────────────
      case "AssignmentStatement": {
        const s = node as AssignStmt;
        const tempRegs: number[] = [];

        // Evaluate all RHS first
        for (let i = 0; i < s.values.length; i++) {
          const r = p.topReg();
          this.compileExprToReg(s.values[i], r);
          tempRegs.push(r);
          p.allocReg();
        }

        // Assign to LHS targets
        for (let i = 0; i < s.targets.length; i++) {
          const src = tempRegs[i] ?? (p.emit(Op.LOADNIL, p.topReg(), 0, 0), p.topReg() - 1);
          this.assignTarget(s.targets[i], src);
        }

        p.freeReg(tempRegs.length);
        break;
      }

      // ── Do block ─────────────────────────────────────────
      case "DoStatement": {
        this.compileBlock((node as DoStmt).body);
        break;
      }

      // ── While ────────────────────────────────────────────
      case "WhileStatement": {
        const s    = node as WhileStmt;
        const loopStart = p.currentPc();
        const condReg   = p.topReg();
        this.compileExprToReg(s.condition, condReg);
        const jfwd = p.emit(Op.TEST, condReg, 0, 0);
        const jmp  = p.emitsBx(Op.JMP, 0, 0);          // forward jump (exit)
        this.compileBlock(s.body);
        p.emitsBx(Op.JMP, 0, loopStart - p.currentPc() - 1);
        p.patchJump(jfwd, p.currentPc());
        p.patchJump(jmp,  p.currentPc());
        break;
      }

      // ── Numeric for ──────────────────────────────────────
      case "NumericForStatement": {
        const s    = node as NumericFor;
        const base = p.allocReg();   // limit
        const lim  = p.allocReg();
        const step = p.allocReg();
        const var_ = p.allocReg();

        this.compileExprToReg(s.start, base);
        this.compileExprToReg(s.limit, lim);
        if (s.step) this.compileExprToReg(s.step, step);
        else p.emit(Op.LOADK, step, 0, 0); // step default = K[1.0]

        const prep = p.emitsBx(Op.FORPREP, base, 0);
        const loopPc = p.currentPc();
        p.locals.push({ name: s.name, reg: var_,
                        depth: (p as any).depth + 1, captured: false });
        this.compileBlock(s.body);
        p.locals.pop();
        const loopInstr = p.emitsBx(Op.FORLOOP, base, loopPc - p.currentPc() - 1);
        p.patchJump(prep, p.currentPc() - 1);
        p.freeReg(4);
        break;
      }

      // ── Return ────────────────────────────────────────────
      case "ReturnStatement": {
        const s    = node as ReturnStmt;
        const base = p.topReg();
        for (const v of s.values) {
          this.compileExprToReg(v, p.allocReg());
        }
        p.emit(Op.RETURN, base, s.values.length + 1, 0);
        break;
      }

      // ── Function call (as statement) ──────────────────────
      case "CallStatement":
      case "CallExpression": {
        const expr = (node as ExprStmt).expression as CallExpr;
        const base = p.topReg();
        this.compileCall(expr, base, 1 /* no results */);
        break;
      }

      // ── If ────────────────────────────────────────────────
      case "IfStatement": {
        this.compileIf(node as IfStmt);
        break;
      }

      // ── Local function ────────────────────────────────────
      case "LocalFunction": {
        const s = node as LocalFuncStmt;
        const reg = p.addLocal(s.name);
        const sub = this.compileFunc(s.func);
        const idx = p.protos.length;
        p.protos.push(sub);
        p.emitBx(Op.CLOSURE, reg, idx);
        break;
      }

      default:
        // TODO: add more statement types as needed
        break;
    }
  }

  // ── If statement (with elseif chain) ─────────────────────
  private compileIf(node: IfStmt) {
    const p     = this.proto;
    const exits: number[] = [];

    const condReg = p.topReg();
    this.compileExprToReg(node.condition, condReg);
    const jfalse = p.emitsBx(Op.JMP, 0, 0);   // jump if false

    this.compileBlock(node.consequent);
    exits.push(p.emitsBx(Op.JMP, 0, 0));      // jump past else

    p.patchJump(jfalse, p.currentPc());

    if (node.alternate) {
      if (node.alternate.type === "IfStatement") {
        this.compileIf(node.alternate as IfStmt);
      } else {
        this.compileBlock(node.alternate as Block);
      }
    }

    const endPc = p.currentPc();
    for (const e of exits) p.patchJump(e, endPc);
  }

  // ── Expression → register ────────────────────────────────
  private compileExprToReg(node: Expression, dst: number) {
    const p = this.proto;

    switch (node.type) {
      case "NilLiteral":
        p.emit(Op.LOADNIL, dst, dst, 0);
        break;
      case "TrueLiteral":
        p.emit(Op.LOADBOOL, dst, 1, 0);
        break;
      case "FalseLiteral":
        p.emit(Op.LOADBOOL, dst, 0, 0);
        break;
      case "NumberLiteral": {
        const ki = p.addConst((node as NumberExpr).value);
        p.emitBx(Op.LOADK, dst, ki);
        break;
      }
      case "StringLiteral": {
        const ki = p.addConst((node as StringExpr).value);
        p.emitBx(Op.LOADK, dst, ki);
        break;
      }
      case "VarArgExpression":
        p.emit(Op.VARARG, dst, 1, 0);
        break;

      case "Identifier": {
        const name = (node as NameExpr).name;
        const local = p.resolveLocal(name);
        if (local !== null) {
          if (local !== dst) p.emit(Op.MOVE, dst, local, 0);
        } else {
          // Global access via _ENV upvalue
          const ki = p.addConst(name);
          p.emitBx(Op.GETGLOBAL, dst, ki);
        }
        break;
      }

      case "MemberExpression": {
        const f   = node as FieldExpr;
        const obj = p.allocReg();
        this.compileExprToReg(f.object, obj);
        const ki  = p.constRK(f.field);
        p.emit(Op.GETTABLE, dst, obj, ki);
        p.freeReg();
        break;
      }

      case "IndexExpression": {
        const ix  = node as IndexExpr;
        const obj = p.allocReg();
        this.compileExprToReg(ix.object, obj);
        const idxR = p.allocReg();
        this.compileExprToReg(ix.index, idxR);
        p.emit(Op.GETTABLE, dst, obj, idxR);
        p.freeReg(2);
        break;
      }

      case "BinaryExpression":
        this.compileBinop(node as BinopExpr, dst);
        break;

      case "UnaryExpression":
        this.compileUnop(node as UnopExpr, dst);
        break;

      case "CallExpression":
        this.compileCall(node as CallExpr, dst, 2 /* one result */);
        break;

      case "FunctionExpression": {
        const sub = this.compileFunc(node as FuncExpr);
        const idx = p.protos.length;
        p.protos.push(sub);
        p.emitBx(Op.CLOSURE, dst, idx);
        break;
      }

      case "TableConstructor":
        this.compileTable(node as TableExpr, dst);
        break;

      default:
        p.emit(Op.LOADNIL, dst, dst, 0);   // fallback
    }
  }

  // ── Binary operation ─────────────────────────────────────
  private compileBinop(node: BinopExpr, dst: number) {
    const p = this.proto;
    const opMap: Record<string, Op> = {
      "+": Op.ADD,  "-": Op.SUB,  "*": Op.MUL,  "/": Op.DIV,
      "%": Op.MOD,  "^": Op.POW, "//": Op.IDIV,
      "&": Op.BAND, "|": Op.BOR, "~": Op.BXOR,
      "<<": Op.SHL, ">>": Op.SHR,
    };

    if (node.op === "..") {
      const l = p.allocReg(); const r = p.allocReg();
      this.compileExprToReg(node.left, l);
      this.compileExprToReg(node.right, r);
      p.emit(Op.CONCAT, dst, l, r);
      p.freeReg(2);
      return;
    }

    const luaOp = opMap[node.op];
    if (luaOp !== undefined) {
      const l = p.allocReg(); const r = p.allocReg();
      this.compileExprToReg(node.left,  l);
      this.compileExprToReg(node.right, r);
      p.emit(luaOp, dst, l, r);
      p.freeReg(2);
    }
  }

  // ── Unary operation ──────────────────────────────────────
  private compileUnop(node: UnopExpr, dst: number) {
    const p = this.proto;
    const r = p.allocReg();
    this.compileExprToReg(node.operand, r);
    switch (node.op) {
      case "-":   p.emit(Op.UNM,  dst, r, 0); break;
      case "not": p.emit(Op.NOT,  dst, r, 0); break;
      case "#":   p.emit(Op.LEN,  dst, r, 0); break;
      case "~":   p.emit(Op.BNOT, dst, r, 0); break;
    }
    p.freeReg();
  }

  // ── Function call ────────────────────────────────────────
  private compileCall(node: CallExpr, dst: number, wantedResults: number) {
    const p    = this.proto;
    const base = p.topReg();

    // Callee
    if (node.callee.type === "MemberExpression") {
      // Method call: SELF
      const m   = node.callee as FieldExpr;
      const obj = p.allocReg();
      this.compileExprToReg(m.object, obj);
      const ki  = p.constRK(m.field);
      p.emit(Op.SELF, base, obj, ki);
      p.allocReg();                 // A+1 slot for self
    } else {
      this.compileExprToReg(node.callee, base);
      p.allocReg();
    }

    for (const arg of node.args) {
      const r = p.allocReg();
      this.compileExprToReg(arg, r);
    }

    const argCount = node.args.length + 1;
    p.emit(Op.CALL, base, argCount + 1, wantedResults);
    p.freeReg(p.topReg() - dst - (wantedResults === 1 ? 0 : 1));
  }

  // ── Assignment target ─────────────────────────────────────
  private assignTarget(target: Expression, srcReg: number) {
    const p = this.proto;
    switch (target.type) {
      case "Identifier": {
        const name  = (target as NameExpr).name;
        const local = p.resolveLocal(name);
        if (local !== null) {
          if (local !== srcReg) p.emit(Op.MOVE, local, srcReg, 0);
        } else {
          const ki = p.addConst(name);
          p.emitBx(Op.SETGLOBAL, srcReg, ki);
        }
        break;
      }
      case "MemberExpression": {
        const f   = target as FieldExpr;
        const obj = p.allocReg();
        this.compileExprToReg(f.object, obj);
        p.emit(Op.SETTABLE, obj, p.constRK(f.field), srcReg);
        p.freeReg();
        break;
      }
      case "IndexExpression": {
        const ix  = target as IndexExpr;
        const obj = p.allocReg();
        this.compileExprToReg(ix.object, obj);
        const key = p.allocReg();
        this.compileExprToReg(ix.index, key);
        p.emit(Op.SETTABLE, obj, key, srcReg);
        p.freeReg(2);
        break;
      }
    }
  }

  // ── Table constructor ─────────────────────────────────────
  private compileTable(node: TableExpr, dst: number) {
    const p = this.proto;
    p.emit(Op.NEWTABLE, dst, 0, 0);
    let arrIdx = 1;
    for (const field of node.fields) {
      const val = p.allocReg();
      this.compileExprToReg(field.value, val);
      if (!field.key) {
        // Array-style: SETLIST deferred
        const ki = p.constRK(arrIdx++);
        p.emit(Op.SETTABLE, dst, ki, val);
      } else {
        const key = p.allocReg();
        this.compileExprToReg(field.key, key);
        p.emit(Op.SETTABLE, dst, key, val);
        p.freeReg();
      }
      p.freeReg();
    }
  }

  // ── Nested function prototype ─────────────────────────────
  private compileFunc(node: FuncExpr): LuauProto {
    const parent = this.proto;
    const child  = new ProtoBuilder();
    child.numParams = node.params.length;
    child.isVararg  = node.isVararg;

    // _ENV upvalue inherited from parent
    child.upvals.push({ instack: false, idx: 0, name: "_ENV" });
    child.upvalMap.set("_ENV", 0);

    // Push params as locals
    for (const p of node.params) {
      const reg = child.allocReg();
      child.locals.push({ name: p, reg, depth: 0, captured: false });
    }

    const savedProto = this.proto;
    this.proto = child;
    this.compileBlock(node.body);
    child.emit(Op.RETURN, 0, 1, 0);
    this.proto = savedProto;

    return child.build();
  }
}

// ── Convenience top-level function ───────────────────────────
export function compile(block: Block, opts?: CompileOptions): LuauProto {
  return new Compiler(opts).compile(block);
}

