import { Token, TokenType } from "../lexer/lexer"
import * as AST from "../ast/types"

export class Parser {
  private tokens: Token[]
  private pos: number = 0
  private errors: { message: string; loc: AST.SourceLocation }[] = []

  constructor(tokens: Token[]) {
    this.tokens = tokens
  }

  getErrors() { return this.errors }

  private peek(offset = 0): Token {
    return this.tokens[this.pos + offset] || this.tokens[this.tokens.length - 1]
  }

  private advance(): Token {
    const t = this.tokens[this.pos]
    if (this.pos < this.tokens.length - 1) this.pos++
    return t
  }

  private check(type: TokenType): boolean {
    return this.peek().type === type
  }

  private match(...types: TokenType[]): boolean {
    for (const t of types) if (this.check(t)) { this.advance(); return true }
    return false
  }

  private expect(type: TokenType): Token {
    if (!this.check(type)) {
      const t = this.peek()
      this.errors.push({ message: `Expected '${type}' got '${t.type}' ('${t.value}')`, loc: this.loc() })
    }
    return this.advance()
  }

  private loc(): AST.SourceLocation {
    const t = this.peek()
    return { line: t.line, column: t.column, pos: t.pos }
  }

  parse(): AST.Block {
    const block = this.parseBlock()
    this.expect("EOF")
    return block
  }

  private parseBlock(): AST.Block {
    const loc = this.loc()
    const body: AST.Statement[] = []
    while (!this.isBlockEnd()) {
      const stmt = this.parseStatement()
      if (stmt) body.push(stmt)
      this.match(";")
    }
    return { kind: "Block", body, loc }
  }

  private isBlockEnd(): boolean {
    const t = this.peek().type
    return t === "EOF" || t === "end" || t === "else" || t === "elseif" || t === "until"
  }

  private parseStatement(): AST.Statement | null {
    const loc = this.loc()
    const t = this.peek().type

    switch (t) {
      case "if":       return this.parseIf()
      case "while":    return this.parseWhile()
      case "do":       return this.parseDo()
      case "for":      return this.parseFor()
      case "repeat":   return this.parseRepeat()
      case "function": return this.parseFunctionDecl()
      case "local":    return this.parseLocal()
      case "return":   return this.parseReturn()
      case "break":    this.advance(); return { kind: "BreakStatement", loc }
      case "continue": this.advance(); return { kind: "ContinueStatement", loc }
      case "goto":     this.advance(); this.advance(); return null
      case "::":       this.advance(); this.advance(); this.expect("::"); return null
      default:         return this.parseExpressionStatement()
    }
  }

  private parseIf(): AST.IfStatement {
    const loc = this.loc()
    const clauses: AST.IfClause[] = []
    this.expect("if")
    clauses.push({ condition: this.parseExpression(), body: (this.expect("then"), this.parseBlock()), loc })
    while (this.check("elseif")) {
      const eloc = this.loc()
      this.advance()
      clauses.push({ condition: this.parseExpression(), body: (this.expect("then"), this.parseBlock()), loc: eloc })
    }
    if (this.match("else")) {
      const eloc = this.loc()
      clauses.push({ condition: null, body: this.parseBlock(), loc: eloc })
    }
    this.expect("end")
    return { kind: "IfStatement", clauses, loc }
  }

  private parseWhile(): AST.WhileStatement {
    const loc = this.loc()
    this.expect("while")
    const condition = this.parseExpression()
    this.expect("do")
    const body = this.parseBlock()
    this.expect("end")
    return { kind: "WhileStatement", condition, body, loc }
  }

  private parseDo(): AST.DoStatement {
    const loc = this.loc()
    this.expect("do")
    const body = this.parseBlock()
    this.expect("end")
    return { kind: "DoStatement", body, loc }
  }

  private parseFor(): AST.NumericFor | AST.GenericFor {
    const loc = this.loc()
    this.expect("for")
    const firstName = this.parseIdentifier()
    if (this.match("=")) {
      const start = this.parseExpression()
      this.expect(",")
      const limit = this.parseExpression()
      const step = this.match(",") ? this.parseExpression() : null
      this.expect("do")
      const body = this.parseBlock()
      this.expect("end")
      return { kind: "NumericFor", name: firstName, start, limit, step, body, loc }
    }
    const names = [firstName]
    while (this.match(",")) names.push(this.parseIdentifier())
    this.expect("in")
    const iterators = this.parseExpressionList()
    this.expect("do")
    const body = this.parseBlock()
    this.expect("end")
    return { kind: "GenericFor", names, iterators, body, loc }
  }

  private parseRepeat(): AST.RepeatStatement {
    const loc = this.loc()
    this.expect("repeat")
    const body = this.parseBlock()
    this.expect("until")
    const condition = this.parseExpression()
    return { kind: "RepeatStatement", body, condition, loc }
  }

  private parseFunctionDecl(): AST.FunctionDeclaration {
    const loc = this.loc()
    this.expect("function")
    let name: AST.Expression = this.parseIdentifier()
    let isMethod = false
    while (this.match(".")) {
      const field = this.parseIdentifier()
      name = { kind: "FieldExpression", object: name, field, loc: this.loc() }
    }
    if (this.match(":")) {
      const method = this.parseIdentifier()
      name = { kind: "FieldExpression", object: name, field: method, loc: this.loc() }
      isMethod = true
    }
    const { params, hasVarArg } = this.parseFunctionParams(isMethod)
    const body = this.parseBlock()
    this.expect("end")
    return { kind: "FunctionDeclaration", name, isMethod, params, hasVarArg, body, loc }
  }

  private parseLocal(): AST.LocalStatement | AST.LocalFunction {
    const loc = this.loc()
    this.expect("local")
    if (this.match("function")) {
      const name = this.parseIdentifier()
      const { params, hasVarArg } = this.parseFunctionParams(false)
      const body = this.parseBlock()
      this.expect("end")
      return { kind: "LocalFunction", name, params, hasVarArg, body, loc }
    }
    const names: AST.Identifier[] = [this.parseIdentifier()]
    while (this.match(",")) names.push(this.parseIdentifier())
    const values = this.match("=") ? this.parseExpressionList() : []
    return { kind: "LocalStatement", names, values, loc }
  }

  private parseReturn(): AST.ReturnStatement {
    const loc = this.loc()
    this.expect("return")
    const values = this.isBlockEnd() || this.check(";") ? [] : this.parseExpressionList()
    this.match(";")
    return { kind: "ReturnStatement", values, loc }
  }

  private parseExpressionStatement(): AST.ExpressionStatement {
    const loc = this.loc()
    const expr = this.parseSuffixExpression()

    if (this.check("=") || this.check(",")) {
      const targets: AST.Expression[] = [expr]
      while (this.match(",")) targets.push(this.parseSuffixExpression())
      this.expect("=")
      const values = this.parseExpressionList()
      return { kind: "ExpressionStatement", expression: { kind: "CallExpression", callee: targets[0], args: values, loc } as any, loc }
    }

    if (expr.kind !== "CallExpression" && expr.kind !== "MethodCallExpression") {
      this.errors.push({ message: "Expected call expression", loc })
    }
    return { kind: "ExpressionStatement", expression: expr as AST.CallExpression | AST.MethodCallExpression, loc }
  }

  private parseFunctionParams(isMethod: boolean): { params: AST.Identifier[]; hasVarArg: boolean } {
    this.expect("(")
    const params: AST.Identifier[] = []
    let hasVarArg = false
    if (isMethod) params.push({ kind: "Identifier", name: "self", loc: this.loc() })
    if (!this.check(")")) {
      do {
        if (this.check("...")) { this.advance(); hasVarArg = true; break }
        params.push(this.parseIdentifier())
      } while (this.match(","))
    }
    this.expect(")")
    return { params, hasVarArg }
  }

  private parseExpressionList(): AST.Expression[] {
    const list = [this.parseExpression()]
    while (this.match(",")) list.push(this.parseExpression())
    return list
  }

  private parseExpression(): AST.Expression {
    return this.parseOr()
  }

  private parseOr(): AST.Expression {
    let left = this.parseAnd()
    while (this.check("or")) {
      const loc = this.loc(); this.advance()
      left = { kind: "BinaryExpression", operator: "or", left, right: this.parseAnd(), loc }
    }
    return left
  }

  private parseAnd(): AST.Expression {
    let left = this.parseComparison()
    while (this.check("and")) {
      const loc = this.loc(); this.advance()
      left = { kind: "BinaryExpression", operator: "and", left, right: this.parseComparison(), loc }
    }
    return left
  }

  private parseComparison(): AST.Expression {
    let left = this.parseBitOr()
    const ops = new Set(["<", ">", "<=", ">=", "==", "~="])
    while (ops.has(this.peek().type)) {
      const loc = this.loc(); const op = this.advance().value
      left = { kind: "BinaryExpression", operator: op, left, right: this.parseBitOr(), loc }
    }
    return left
  }

  private parseBitOr(): AST.Expression {
    let left = this.parseBitXor()
    while (this.check("|")) {
      const loc = this.loc(); this.advance()
      left = { kind: "BinaryExpression", operator: "|", left, right: this.parseBitXor(), loc }
    }
    return left
  }

  private parseBitXor(): AST.Expression {
    let left = this.parseBitAnd()
    while (this.check("~")) {
      const loc = this.loc(); this.advance()
      left = { kind: "BinaryExpression", operator: "~", left, right: this.parseBitAnd(), loc }
    }
    return left
  }

  private parseBitAnd(): AST.Expression {
    let left = this.parseBitShift()
    while (this.check("&")) {
      const loc = this.loc(); this.advance()
      left = { kind: "BinaryExpression", operator: "&", left, right: this.parseBitShift(), loc }
    }
    return left
  }

  private parseBitShift(): AST.Expression {
    let left = this.parseConcat()
    while (this.check("<<") || this.check(">>")) {
      const loc = this.loc(); const op = this.advance().value
      left = { kind: "BinaryExpression", operator: op, left, right: this.parseConcat(), loc }
    }
    return left
  }

  private parseConcat(): AST.Expression {
    const left = this.parseAddSub()
    if (this.check("..")) {
      const loc = this.loc(); this.advance()
      return { kind: "BinaryExpression", operator: "..", left, right: this.parseConcat(), loc }
    }
    return left
  }

  private parseAddSub(): AST.Expression {
    let left = this.parseMulDiv()
    while (this.check("+") || this.check("-")) {
      const loc = this.loc(); const op = this.advance().value
      left = { kind: "BinaryExpression", operator: op, left, right: this.parseMulDiv(), loc }
    }
    return left
  }

  private parseMulDiv(): AST.Expression {
    let left = this.parseUnary()
    while (this.check("*") || this.check("/") || this.check("%") || this.check("//")) {
      const loc = this.loc(); const op = this.advance().value
      left = { kind: "BinaryExpression", operator: op, left, right: this.parseUnary(), loc }
    }
    return left
  }

  private parseUnary(): AST.Expression {
    const loc = this.loc()
    if (this.check("not")) { this.advance(); return { kind: "UnaryExpression", operator: "not", operand: this.parseUnary(), loc } }
    if (this.check("-"))   { this.advance(); return { kind: "UnaryExpression", operator: "-",   operand: this.parseUnary(), loc } }
    if (this.check("#"))   { this.advance(); return { kind: "UnaryExpression", operator: "#",   operand: this.parseUnary(), loc } }
    if (this.check("~"))   { this.advance(); return { kind: "UnaryExpression", operator: "~",   operand: this.parseUnary(), loc } }
    return this.parsePower()
  }

  private parsePower(): AST.Expression {
    const base = this.parseSuffixExpression()
    if (this.check("^")) {
      const loc = this.loc(); this.advance()
      return { kind: "BinaryExpression", operator: "^", left: base, right: this.parseUnary(), loc }
    }
    return base
  }

  private parseSuffixExpression(): AST.Expression {
    let expr = this.parsePrimaryExpression()
    while (true) {
      const loc = this.loc()
      if (this.match(".")) {
        const field = this.parseIdentifier()
        expr = { kind: "FieldExpression", object: expr, field, loc }
      } else if (this.match("[")) {
        const index = this.parseExpression()
        this.expect("]")
        expr = { kind: "IndexExpression", object: expr, index, loc }
      } else if (this.match(":")) {
        const method = this.parseIdentifier()
        const args = this.parseCallArgs()
        expr = { kind: "MethodCallExpression", object: expr, method, args, loc }
      } else if (this.check("(") || this.check("{") || this.check("String")) {
        const args = this.parseCallArgs()
        expr = { kind: "CallExpression", callee: expr, args, loc }
      } else break
    }
    return expr
  }

  private parseCallArgs(): AST.Expression[] {
    const loc = this.loc()
    if (this.match("(")) {
      const args = this.check(")") ? [] : this.parseExpressionList()
      this.expect(")")
      return args
    }
    if (this.check("{")) return [this.parseTableConstructor()]
    if (this.check("String")) {
      const t = this.advance()
      return [{ kind: "StringLiteral", value: t.value, raw: t.value, loc }]
    }
    this.errors.push({ message: "Expected function arguments", loc })
    return []
  }

  private parsePrimaryExpression(): AST.Expression {
    const loc = this.loc()
    const t = this.peek()
    switch (t.type) {
      case "Name":   this.advance(); return { kind: "Identifier", name: t.value, loc }
      case "Number": this.advance(); return { kind: "NumberLiteral", value: parseFloat(t.value), raw: t.value, loc }
      case "String": this.advance(); return { kind: "StringLiteral", value: t.value, raw: t.value, loc }
      case "true":   this.advance(); return { kind: "BooleanLiteral", value: true, loc }
      case "false":  this.advance(); return { kind: "BooleanLiteral", value: false, loc }
      case "nil":    this.advance(); return { kind: "NilLiteral", loc }
      case "...":    this.advance(); return { kind: "VarArgLiteral", loc }
      case "(": {
        this.advance()
        const expr = this.parseExpression()
        this.expect(")")
        return expr
      }
      case "function": {
        this.advance()
        const { params, hasVarArg } = this.parseFunctionParams(false)
        const body = this.parseBlock()
        this.expect("end")
        return { kind: "FunctionExpression", params, hasVarArg, body, loc }
      }
      case "{": return this.parseTableConstructor()
      default:
        this.errors.push({ message: `Unexpected token: ${t.type} ('${t.value}')`, loc })
        this.advance()
        return { kind: "NilLiteral", loc }
    }
  }

  private parseTableConstructor(): AST.TableConstructor {
    const loc = this.loc()
    this.expect("{")
    const fields: AST.TableEntry[] = []
    while (!this.check("}") && !this.check("EOF")) {
      const floc = this.loc()
      if (this.check("[")) {
        this.advance()
        const key = this.parseExpression()
        this.expect("]"); this.expect("=")
        const value = this.parseExpression()
        fields.push({ kind: "TableKey", key, value, loc: floc })
      } else if (this.check("Name") && this.peek(1).type === "=") {
        const key = this.parseIdentifier()
        this.advance()
        const value = this.parseExpression()
        fields.push({ kind: "TableKeyString", key, value, loc: floc })
      } else {
        const value = this.parseExpression()
        fields.push({ kind: "TableField", value, loc: floc })
      }
      if (!this.match(",") && !this.match(";")) break
    }
    this.expect("}")
    return { kind: "TableConstructor", fields, loc }
  }

  private parseIdentifier(): AST.Identifier {
    const loc = this.loc()
    const t = this.peek()
    if (t.type !== "Name") {
      this.errors.push({ message: `Expected identifier, got ${t.type}`, loc })
    }
    this.advance()
    return { kind: "Identifier", name: t.value, loc }
  }
}

export function parse(tokens: Token[]): { ast: AST.Block; errors: { message: string; loc: AST.SourceLocation }[] } {
  const parser = new Parser(tokens)
  const ast = parser.parse()
  return { ast, errors: parser.getErrors() }
}

