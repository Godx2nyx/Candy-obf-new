import * as AST from "../ast/types"

export interface StringEntry {
  index: number
  encrypted: number[]
  key: number
}

export class StringEncryptor {
  private table: StringEntry[] = []
  private map: Map<string, number> = new Map()
  private seed: number
  private tableVarName: string
  private decoderFnName: string

  constructor(seed: number, tableVarName: string, decoderFnName: string) {
    this.seed = seed
    this.tableVarName = tableVarName
    this.decoderFnName = decoderFnName
  }

  private xorEncrypt(str: string, key: number): number[] {
    const bytes: number[] = []
    for (let i = 0; i < str.length; i++) {
      const charCode = str.charCodeAt(i)
      const k = (key + i * 7 + i * i * 3) & 0xFF
      bytes.push(charCode ^ k)
    }
    return bytes
  }

  private rng(): number {
    this.seed = (this.seed * 1664525 + 1013904223) & 0xFFFFFFFF
    return (this.seed >>> 0) & 0xFF
  }

  addString(value: string): number {
    if (this.map.has(value)) return this.map.get(value)!
    const key = this.rng()
    const encrypted = this.xorEncrypt(value, key)
    const index = this.table.length
    this.table.push({ index, encrypted, key })
    this.map.set(value, index)
    return index
  }

  getTable(): StringEntry[] { return this.table }

  
  generateDecryptorCode(): string {
    if (this.table.length === 0) return ""

    const tableEntries = this.table.map(e => {
      const bytes = e.encrypted.join(",")
      return `{${e.key},{${bytes}}}`
    }).join(",")

    return [
      `local ${this.tableVarName}={${tableEntries}}`,
      `local function ${this.decoderFnName}(i)`,
      `  local e=${this.tableVarName}[i+1]`,
      `  local k=e[1]`,
      `  local b=e[2]`,
      `  local r=""`,
      `  for j=1,#b do`,
      `    local c=b[j]`,
      `    local x=(k+(j-1)*7+(j-1)*(j-1)*3)%256`,
      `    r=r..string.char(c~x)`,
      `  end`,
      `  return r`,
      `end`
    ].join("\n")
  }

  transformAST(node: AST.Block, skipShortStrings = true): AST.Block {
    return this.transformBlock(node, skipShortStrings)
  }

  private transformBlock(block: AST.Block, skip: boolean): AST.Block {
    return { ...block, body: block.body.map(s => this.transformStmt(s, skip)) }
  }

  private transformStmt(stmt: AST.Statement, skip: boolean): AST.Statement {
    switch (stmt.kind) {
      case "LocalStatement":
        return { ...stmt, values: stmt.values.map(v => this.transformExpr(v, skip)) }
      case "AssignStatement":
        return {
          ...stmt,
          targets: stmt.targets.map(t => this.transformExpr(t, skip)),
          values: stmt.values.map(v => this.transformExpr(v, skip))
        }
      case "ReturnStatement":
        return { ...stmt, values: stmt.values.map(v => this.transformExpr(v, skip)) }
      case "ExpressionStatement":
        return { ...stmt, expression: this.transformExpr(stmt.expression, skip) as any }
      case "WhileStatement":
        return { ...stmt, condition: this.transformExpr(stmt.condition, skip), body: this.transformBlock(stmt.body, skip) }
      case "RepeatStatement":
        return { ...stmt, body: this.transformBlock(stmt.body, skip), condition: this.transformExpr(stmt.condition, skip) }
      case "IfStatement":
        return {
          ...stmt,
          clauses: stmt.clauses.map(c => ({
            ...c,
            condition: c.condition ? this.transformExpr(c.condition, skip) : null,
            body: this.transformBlock(c.body, skip)
          }))
        }
      case "NumericFor":
        return { ...stmt, body: this.transformBlock(stmt.body, skip) }
      case "GenericFor":
        return { ...stmt, iterators: stmt.iterators.map(i => this.transformExpr(i, skip)), body: this.transformBlock(stmt.body, skip) }
      case "FunctionDeclaration":
      case "LocalFunction":
        return { ...stmt, body: this.transformBlock(stmt.body, skip) }
      case "DoStatement":
        return { ...stmt, body: this.transformBlock(stmt.body, skip) }
      default:
        return stmt
    }
  }

  private transformExpr(expr: AST.Expression, skip: boolean): AST.Expression {
    switch (expr.kind) {
      case "StringLiteral": {
        if (skip && expr.value.length <= 2) return expr
        const idx = this.addString(expr.value)
        const loc = expr.loc
        return {
          kind: "CallExpression",
          callee: { kind: "Identifier", name: this.decoderFnName, loc },
          args: [{ kind: "NumberLiteral", value: idx, raw: String(idx), loc }],
          loc
        }
      }
      case "BinaryExpression":
        return { ...expr, left: this.transformExpr(expr.left, skip), right: this.transformExpr(expr.right, skip) }
      case "UnaryExpression":
        return { ...expr, operand: this.transformExpr(expr.operand, skip) }
      case "IndexExpression":
        return { ...expr, object: this.transformExpr(expr.object, skip), index: this.transformExpr(expr.index, skip) }
      case "FieldExpression":
        return { ...expr, object: this.transformExpr(expr.object, skip) }
      case "CallExpression":
        return { ...expr, callee: this.transformExpr(expr.callee, skip), args: expr.args.map(a => this.transformExpr(a, skip)) }
      case "MethodCallExpression":
        return { ...expr, object: this.transformExpr(expr.object, skip), args: expr.args.map(a => this.transformExpr(a, skip)) }
      case "FunctionExpression":
        return { ...expr, body: this.transformBlock(expr.body, skip) }
      case "TableConstructor":
        return {
          ...expr,
          fields: expr.fields.map(f => {
            switch (f.kind) {
              case "TableField": return { ...f, value: this.transformExpr(f.value, skip) }
              case "TableKey": return { ...f, key: this.transformExpr(f.key, skip), value: this.transformExpr(f.value, skip) }
              case "TableKeyString": return { ...f, value: this.transformExpr(f.value, skip) }
            }
          })
        }
      default:
        return expr
    }
  }
}
