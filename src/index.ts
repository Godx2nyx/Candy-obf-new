import { Lexer } from "./lexer/lexer"
import { parse } from "./parser/parser"

export function tokenize(source: string) {
  const lexer = new Lexer(source)
  return { tokens: lexer.tokenize(), errors: lexer.getErrors() }
}

export function parseSource(source: string) {
  const { tokens, errors: lexErrors } = tokenize(source)
  const { ast, errors: parseErrors } = parse(tokens)
  return { ast, errors: [...lexErrors.map(e => ({ message: e.message, loc: { line: e.line, column: e.column, pos: 0 } })), ...parseErrors] }
}

