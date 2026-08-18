export type TokenType =
  | "Number" | "String" | "Name" | "EOF"
  | "+" | "-" | "*" | "/" | "%" | "^" | "#"
  | "&" | "|" | "~" | "<<" | ">>"
  | "//"
  | "==" | "~=" | "<=" | ">=" | "<" | ">"
  | "=" | "(" | ")" | "{" | "}" | "[" | "]"
  | "::" | ";" | ":" | "," | "." | ".." | "..."
  | "and" | "break" | "continue" | "do" | "else"
  | "elseif" | "end" | "false" | "for" | "function"
  | "goto" | "if" | "in" | "local" | "nil"
  | "not" | "or" | "repeat" | "return" | "then"
  | "true" | "until" | "while"

export interface Token {
  type: TokenType
  value: string
  line: number
  column: number
  pos: number
}

const KEYWORDS = new Set([
  "and","break","continue","do","else","elseif","end",
  "false","for","function","goto","if","in","local",
  "nil","not","or","repeat","return","then","true",
  "until","while"
])

export class Lexer {
  private src: string
  private pos: number = 0
  private line: number = 1
  private column: number = 1
  private tokens: Token[] = []
  private errors: { message: string; line: number; column: number }[] = []

  constructor(source: string) {
    this.src = source
  }

  getErrors() { return this.errors }

  tokenize(): Token[] {
    while (this.pos < this.src.length) {
      this.skipWhitespaceAndComments()
      if (this.pos >= this.src.length) break

      const ch = this.src[this.pos]
      const startLine = this.line
      const startCol = this.column
      const startPos = this.pos

      if (ch === '\n') { this.advance(); continue }

      if (this.isDigit(ch) || (ch === '.' && this.isDigit(this.src[this.pos + 1] || ''))) {
        this.tokens.push(this.readNumber(startLine, startCol, startPos))
        continue
      }

      if (ch === '"' || ch === "'") {
        this.tokens.push(this.readString(ch, startLine, startCol, startPos))
        continue
      }

      if (ch === '[' && (this.src[this.pos + 1] === '[' || this.src[this.pos + 1] === '=')) {
        const long = this.tryReadLongString(startLine, startCol, startPos)
        if (long) { this.tokens.push(long); continue }
      }

      if (this.isAlpha(ch) || ch === '_') {
        this.tokens.push(this.readName(startLine, startCol, startPos))
        continue
      }

      const op = this.tryReadOperator(startLine, startCol, startPos)
      if (op) { this.tokens.push(op); continue }

      this.errors.push({ message: `Unexpected character: ${ch}`, line: startLine, column: startCol })
      this.advance()
    }

    this.tokens.push({ type: "EOF", value: "", line: this.line, column: this.column, pos: this.pos })
    return this.tokens
  }

  private advance(): string {
    const ch = this.src[this.pos++]
    if (ch === '\n') { this.line++; this.column = 1 }
    else { this.column++ }
    return ch
  }

  private peek(offset = 0): string {
    return this.src[this.pos + offset] || ''
  }

  private isDigit(ch: string) { return ch >= '0' && ch <= '9' }
  private isHex(ch: string) { return this.isDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') }
  private isAlpha(ch: string) { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_' }
  private isAlNum(ch: string) { return this.isAlpha(ch) || this.isDigit(ch) }

  private skipWhitespaceAndComments() {
    while (this.pos < this.src.length) {
      const ch = this.src[this.pos]

      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
        this.advance(); continue
      }

      if (ch === '-' && this.src[this.pos + 1] === '-') {
        this.pos += 2; this.column += 2
        if (this.src[this.pos] === '[') {
          const level = this.checkLongBracket()
          if (level >= 0) { this.skipLongString(level); continue }
        }
        while (this.pos < this.src.length && this.src[this.pos] !== '\n') this.advance()
        continue
      }

      break
    }
  }

  private checkLongBracket(): number {
    let i = this.pos + 1
    let level = 0
    while (i < this.src.length && this.src[i] === '=') { level++; i++ }
    if (i < this.src.length && this.src[i] === '[') return level
    return -1
  }

  private skipLongString(level: number) {
    const closing = ']' + '='.repeat(level) + ']'
    while (this.pos < this.src.length) {
      if (this.src.slice(this.pos, this.pos + closing.length) === closing) {
        this.pos += closing.length; this.column += closing.length; return
      }
      this.advance()
    }
  }

  private readLongString(level: number): string {
    const closing = ']' + '='.repeat(level) + ']'
    const start = this.pos
    if (this.src[this.pos] === '\n') this.advance()
    let result = ''
    while (this.pos < this.src.length) {
      if (this.src.slice(this.pos, this.pos + closing.length) === closing) {
        this.pos += closing.length; this.column += closing.length
        return result
      }
      result += this.src[this.pos]
      this.advance()
    }
    this.errors.push({ message: "Unfinished long string", line: this.line, column: this.column })
    return result
  }

  private tryReadLongString(line: number, col: number, pos: number): Token | null {
    const savedPos = this.pos
    const savedLine = this.line
    const savedCol = this.column

    this.pos++; this.column++
    let level = 0
    while (this.pos < this.src.length && this.src[this.pos] === '=') {
      level++; this.pos++; this.column++
    }
    if (this.src[this.pos] !== '[') {
      this.pos = savedPos; this.line = savedLine; this.column = savedCol
      return null
    }
    this.pos++; this.column++
    const value = this.readLongString(level)
    return { type: "String", value, line, column: col, pos }
  }

  private readNumber(line: number, col: number, pos: number): Token {
    let raw = ''
    if (this.src[this.pos] === '0' && (this.src[this.pos + 1] === 'x' || this.src[this.pos + 1] === 'X')) {
      raw += this.advance() + this.advance()
      while (this.pos < this.src.length && this.isHex(this.src[this.pos])) raw += this.advance()
      if (this.src[this.pos] === '.') {
        raw += this.advance()
        while (this.pos < this.src.length && this.isHex(this.src[this.pos])) raw += this.advance()
      }
      if (this.src[this.pos] === 'p' || this.src[this.pos] === 'P') {
        raw += this.advance()
        if (this.src[this.pos] === '+' || this.src[this.pos] === '-') raw += this.advance()
        while (this.pos < this.src.length && this.isDigit(this.src[this.pos])) raw += this.advance()
      }
    } else {
      while (this.pos < this.src.length && this.isDigit(this.src[this.pos])) raw += this.advance()
      if (this.src[this.pos] === '.') {
        raw += this.advance()
        while (this.pos < this.src.length && this.isDigit(this.src[this.pos])) raw += this.advance()
      }
      if (this.src[this.pos] === 'e' || this.src[this.pos] === 'E') {
        raw += this.advance()
        if (this.src[this.pos] === '+' || this.src[this.pos] === '-') raw += this.advance()
        while (this.pos < this.src.length && this.isDigit(this.src[this.pos])) raw += this.advance()
      }
    }
    return { type: "Number", value: raw, line, column: col, pos }
  }

  private readString(quote: string, line: number, col: number, pos: number): Token {
    this.advance()
    let value = ''
    while (this.pos < this.src.length && this.src[this.pos] !== quote) {
      if (this.src[this.pos] === '\n') { this.errors.push({ message: "Unfinished string", line, column: col }); break }
      if (this.src[this.pos] === '\\') {
        this.advance()
        const esc = this.src[this.pos] || ''
        const escMap: Record<string, string> = {
          'n': '\n', 't': '\t', 'r': '\r', 'a': '\x07', 'b': '\b',
          'f': '\f', 'v': '\v', '\\': '\\', "'": "'", '"': '"'
        }
        if (esc in escMap) { value += escMap[esc]; this.advance() }
        else if (esc === 'x') {
          this.advance()
          let hex = ''
          for (let i = 0; i < 2; i++) { hex += this.src[this.pos]; this.advance() }
          value += String.fromCharCode(parseInt(hex, 16))
        }
        else if (esc === 'z') {
          this.advance()
          while (this.pos < this.src.length && /\s/.test(this.src[this.pos])) this.advance()
        }
        else if (this.isDigit(esc)) {
          let dec = ''
          for (let i = 0; i < 3 && this.isDigit(this.src[this.pos]); i++) { dec += this.src[this.pos]; this.advance() }
          value += String.fromCharCode(parseInt(dec, 10))
        }
        else { value += esc; this.advance() }
      } else {
        value += this.src[this.pos]; this.advance()
      }
    }
    if (this.pos < this.src.length) this.advance()
    return { type: "String", value, line, column: col, pos }
  }

  private readName(line: number, col: number, pos: number): Token {
    let name = ''
    while (this.pos < this.src.length && this.isAlNum(this.src[this.pos])) name += this.advance()
    const type = KEYWORDS.has(name) ? name as TokenType : "Name"
    return { type, value: name, line, column: col, pos }
  }

  private tryReadOperator(line: number, col: number, pos: number): Token | null {
    const ch = this.src[this.pos]
    const ch2 = ch + (this.src[this.pos + 1] || '')
    const ch3 = ch2 + (this.src[this.pos + 2] || '')

    const ops3: Record<string, TokenType> = { "...": "..." }
    const ops2: Record<string, TokenType> = {
      "==": "==", "~=": "~=", "<=": "<=", ">=": ">=",
      "..": "..", "::": "::", "//": "//", "<<": "<<", ">>": ">>"
    }
    const ops1: Record<string, TokenType> = {
      "+": "+", "-": "-", "*": "*", "/": "/", "%": "%", "^": "^",
      "#": "#", "&": "&", "|": "|", "~": "~",
      "<": "<", ">": ">", "=": "=",
      "(": "(", ")": ")", "{": "{", "}": "}", "[": "[", "]": "]",
      ";": ";", ":": ":", ",": ",", ".": "."
    }

    if (ops3[ch3]) { const t = ops3[ch3]; this.pos += 3; this.column += 3; return { type: t, value: ch3, line, column: col, pos } }
    if (ops2[ch2]) { const t = ops2[ch2]; this.pos += 2; this.column += 2; return { type: t, value: ch2, line, column: col, pos } }
    if (ops1[ch]) { const t = ops1[ch]; this.advance(); return { type: t, value: ch, line, column: col, pos } }
    return null
  }
}

