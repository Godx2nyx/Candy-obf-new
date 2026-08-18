import * as AST from "../ast/types"

export interface CodegenOptions {
  minify: boolean
  indent: string
}

export class CodeGenerator {
  private opts: CodegenOptions
  private depth: number = 0

  constructor(opts: Partial<CodegenOptions> = {}) {
    this.opts = {
      minify: opts.minify ?? false,
      indent: opts.indent ?? "  "
    }
  }

  generate(block: AST.Block): string {
    return this.genBlock(block)
  }

  private nl(): string {
    if (this.opts.minify) return " "
    return "\n" + this.opts.indent.repeat(this.depth)
  }

  private sep(): string {
    return this.opts.minify ? " " : "\n"
  }

  private genBlock(block: AST.Block): string {
    if (block.body.length === 0) return ""
    const stmts = block.body.map(s => this.genStmt(s)).filter(s => s !== "")
    return stmts.join(this.sep())
  }

  private genStmt(stmt: AST.Statement): string {
    const ind = this.opts.minify ? "" : this.opts.indent.repeat(this.depth)
    switch (stmt.kind) {
      case "LocalStatement": {
        const names = stmt.names.map(n => n.name).join(",")
        const vals = stmt.values.length > 0 ? "=" + stmt.values.map(v => this.genExpr(v)).join(",") : ""
        return `${ind}local ${names}${vals}`
      }

      case "AssignStatement": {
        const targets = stmt.targets.map(t => this.genExpr(t)).join(",")
        const values = stmt.values.map(v => this.genExpr(v)).join(",")
        return `${ind}${targets}=${values}`
      }

      case "LocalFunction": {
        this.depth++
        const params = stmt.params.map(p => p.name).join(",")
        const hasVarArg = stmt.hasVarArg ? (params ? "," : "") + "..." : ""
        const body = this.genBlock(stmt.body)
        this.depth--
        const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
        return `${ind}local function ${stmt.name.name}(${params}${hasVarArg})${bodyStr}end`
      }

      case "FunctionDeclaration": {
        this.depth++
        const params = stmt.params.filter(p => !stmt.isMethod || p.name !== "self").map(p => p.name).join(",")
        const hasVarArg = stmt.hasVarArg ? (params ? "," : "") + "..." : ""
        const name = this.genExpr(stmt.name)
        const sep2 = stmt.isMethod ? ":" : "."
        const body = this.genBlock(stmt.body)
        this.depth--
        const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
        return `${ind}function ${name}(${params}${hasVarArg})${bodyStr}end`
      }

      case "DoStatement": {
        this.depth++
        const body = this.genBlock(stmt.body)
        this.depth--
        const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
        return `${ind}do${bodyStr}end`
      }

      case "WhileStatement": {
        this.depth++
        const body = this.genBlock(stmt.body)
        this.depth--
        const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
        return `${ind}while ${this.genExpr(stmt.condition)} do${bodyStr}end`
      }

      case "RepeatStatement": {
        this.depth++
        const body = this.genBlock(stmt.body)
        this.depth--
        const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
        return `${ind}repeat${bodyStr}until ${this.genExpr(stmt.condition)}`
      }

      case "IfStatement": {
        const parts: string[] = []
        stmt.clauses.forEach((clause, i) => {
          this.depth++
          const body = this.genBlock(clause.body)
          this.depth--
          const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
          if (i === 0) {
            parts.push(`${ind}if ${this.genExpr(clause.condition!)} then${bodyStr}`)
          } else if (clause.condition === null) {
            parts.push(`else${bodyStr}`)
          } else {
            parts.push(`elseif ${this.genExpr(clause.condition)} then${bodyStr}`)
          }
        })
        return parts.join("") + "end"
      }

      case "NumericFor": {
        this.depth++
        const body = this.genBlock(stmt.body)
        this.depth--
        const step = stmt.step ? "," + this.genExpr(stmt.step) : ""
        const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
        return `${ind}for ${stmt.name.name}=${this.genExpr(stmt.start)},${this.genExpr(stmt.limit)}${step} do${bodyStr}end`
      }

      case "GenericFor": {
        this.depth++
        const body = this.genBlock(stmt.body)
        this.depth--
        const names = stmt.names.map(n => n.name).join(",")
        const iters = stmt.iterators.map(i => this.genExpr(i)).join(",")
        const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
        return `${ind}for ${names} in ${iters} do${bodyStr}end`
      }

      case "ReturnStatement": {
        const vals = stmt.values.map(v => this.genExpr(v)).join(",")
        return `${ind}return${vals ? " " + vals : ""}`
      }

      case "BreakStatement":
        return `${ind}break`

      case "ContinueStatement":
        return `${ind}continue`

      case "ExpressionStatement":
        return `${ind}${this.genExpr(stmt.expression)}`

      default:
        return ""
    }
  }

  private genExpr(expr: AST.Expression): string {
    switch (expr.kind) {
      case "NilLiteral":     return "nil"
      case "BooleanLiteral": return expr.value ? "true" : "false"
      case "VarArgLiteral":  return "..."
      case "NumberLiteral":  return expr.raw
      case "StringLiteral":  return this.escapeString(expr.value)
      case "Identifier":     return expr.name

      case "BinaryExpression": {
        const l = this.needsParens(expr.left, expr, "left") ? `(${this.genExpr(expr.left)})` : this.genExpr(expr.left)
        const r = this.needsParens(expr.right, expr, "right") ? `(${this.genExpr(expr.right)})` : this.genExpr(expr.right)
        return `${l}${expr.operator}${r}`
      }

      case "UnaryExpression": {
        const op = expr.operator === "not" ? "not " : expr.operator
        const operand = expr.operand.kind === "BinaryExpression" ? `(${this.genExpr(expr.operand)})` : this.genExpr(expr.operand)
        return `${op}${operand}`
      }

      case "FieldExpression":
        return `${this.genExpr(expr.object)}.${expr.field.name}`

      case "IndexExpression":
        return `${this.genExpr(expr.object)}[${this.genExpr(expr.index)}]`

      case "CallExpression": {
        const callee = this.genExpr(expr.callee)
        const args = expr.args.map(a => this.genExpr(a)).join(",")
        return `${callee}(${args})`
      }

      case "MethodCallExpression": {
        const obj = this.genExpr(expr.object)
        const args = expr.args.map(a => this.genExpr(a)).join(",")
        return `${obj}:${expr.method.name}(${args})`
      }

      case "FunctionExpression": {
        const params = expr.params.map(p => p.name).join(",")
        const hasVarArg = expr.hasVarArg ? (params ? "," : "") + "..." : ""
        this.depth++
        const body = this.genBlock(expr.body)
        this.depth--
        const ind = this.opts.minify ? "" : this.opts.indent.repeat(this.depth)
        const bodyStr = body ? this.sep() + body + this.sep() + ind : " "
        return `function(${params}${hasVarArg})${bodyStr}end`
      }

      case "TableConstructor": {
        if (expr.fields.length === 0) return "{}"
        const fields = expr.fields.map(f => {
          switch (f.kind) {
            case "TableField":     return this.genExpr(f.value)
            case "TableKey":       return `[${this.genExpr(f.key)}]=${this.genExpr(f.value)}`
            case "TableKeyString": return `${f.key.name}=${this.genExpr(f.value)}`
          }
        }).join(",")
        return `{${fields}}`
      }

      default:
        return "nil"
    }
  }

  private escapeString(str: string): string {
    let result = '"'
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i)
      const ch = str[i]
      if (ch === '"')       result += '\\"'
      else if (ch === '\\') result += '\\\\'
      else if (ch === '\n') result += '\\n'
      else if (ch === '\r') result += '\\r'
      else if (ch === '\t') result += '\\t'
      else if (ch === '\0') result += '\\0'
      else if (code < 32 || code > 126) result += `\\${code}`
      else result += ch
    }
    return result + '"'
  }

  private PREC: Record<string, number> = {
    "or": 1, "and": 2,
    "<": 3, ">": 3, "<=": 3, ">=": 3, "==": 3, "~=": 3,
    "|": 4, "~": 5, "&": 6,
    "<<": 7, ">>": 7,
    "..": 8,
    "+": 9, "-": 9,
    "*": 10, "/": 10, "//": 10, "%": 10,
    "^": 12
  }

  private needsParens(child: AST.Expression, parent: AST.BinaryExpression, side: "left" | "right"): boolean {
    if (child.kind !== "BinaryExpression") return false
    const cp = this.PREC[child.operator] ?? 0
    const pp = this.PREC[parent.operator] ?? 0
    if (cp < pp) return true
    if (cp === pp && side === "right" && parent.operator !== "^" && parent.operator !== "..") return true
    return false
  }
}
