export interface SourceLocation {
  line: number
  column: number
  pos: number
}

export type NodeKind =
  | "Block"
  | "AssignStatement"
  | "LocalStatement"
  | "DoStatement"
  | "WhileStatement"
  | "RepeatStatement"
  | "IfStatement"
  | "NumericFor"
  | "GenericFor"
  | "FunctionDeclaration"
  | "LocalFunction"
  | "ReturnStatement"
  | "BreakStatement"
  | "ContinueStatement"
  | "ExpressionStatement"
  | "NumberLiteral"
  | "StringLiteral"
  | "BooleanLiteral"
  | "NilLiteral"
  | "VarArgLiteral"
  | "Identifier"
  | "BinaryExpression"
  | "UnaryExpression"
  | "IndexExpression"
  | "FieldExpression"
  | "MethodCallExpression"
  | "CallExpression"
  | "FunctionExpression"
  | "TableConstructor"
  | "TableField"
  | "TableKey"
  | "TableKeyString"

export interface BaseNode {
  kind: NodeKind
  loc: SourceLocation
}

export interface Block extends BaseNode {
  kind: "Block"
  body: Statement[]
}

export interface AssignStatement extends BaseNode {
  kind: "AssignStatement"
  targets: Expression[]
  values: Expression[]
}

export interface LocalStatement extends BaseNode {
  kind: "LocalStatement"
  names: Identifier[]
  values: Expression[]
}

export interface DoStatement extends BaseNode {
  kind: "DoStatement"
  body: Block
}

export interface WhileStatement extends BaseNode {
  kind: "WhileStatement"
  condition: Expression
  body: Block
}

export interface RepeatStatement extends BaseNode {
  kind: "RepeatStatement"
  body: Block
  condition: Expression
}

export interface IfClause {
  condition: Expression | null
  body: Block
  loc: SourceLocation
}

export interface IfStatement extends BaseNode {
  kind: "IfStatement"
  clauses: IfClause[]
}

export interface NumericFor extends BaseNode {
  kind: "NumericFor"
  name: Identifier
  start: Expression
  limit: Expression
  step: Expression | null
  body: Block
}

export interface GenericFor extends BaseNode {
  kind: "GenericFor"
  names: Identifier[]
  iterators: Expression[]
  body: Block
}

export interface FunctionDeclaration extends BaseNode {
  kind: "FunctionDeclaration"
  name: Expression
  isMethod: boolean
  params: Identifier[]
  hasVarArg: boolean
  body: Block
}

export interface LocalFunction extends BaseNode {
  kind: "LocalFunction"
  name: Identifier
  params: Identifier[]
  hasVarArg: boolean
  body: Block
}

export interface ReturnStatement extends BaseNode {
  kind: "ReturnStatement"
  values: Expression[]
}

export interface BreakStatement extends BaseNode {
  kind: "BreakStatement"
}

export interface ContinueStatement extends BaseNode {
  kind: "ContinueStatement"
}

export interface ExpressionStatement extends BaseNode {
  kind: "ExpressionStatement"
  expression: CallExpression | MethodCallExpression
}

export interface NumberLiteral extends BaseNode {
  kind: "NumberLiteral"
  value: number
  raw: string
}

export interface StringLiteral extends BaseNode {
  kind: "StringLiteral"
  value: string
  raw: string
}

export interface BooleanLiteral extends BaseNode {
  kind: "BooleanLiteral"
  value: boolean
}

export interface NilLiteral extends BaseNode {
  kind: "NilLiteral"
}

export interface VarArgLiteral extends BaseNode {
  kind: "VarArgLiteral"
}

export interface Identifier extends BaseNode {
  kind: "Identifier"
  name: string
}

export interface BinaryExpression extends BaseNode {
  kind: "BinaryExpression"
  operator: string
  left: Expression
  right: Expression
}

export interface UnaryExpression extends BaseNode {
  kind: "UnaryExpression"
  operator: string
  operand: Expression
}

export interface IndexExpression extends BaseNode {
  kind: "IndexExpression"
  object: Expression
  index: Expression
}

export interface FieldExpression extends BaseNode {
  kind: "FieldExpression"
  object: Expression
  field: Identifier
}

export interface MethodCallExpression extends BaseNode {
  kind: "MethodCallExpression"
  object: Expression
  method: Identifier
  args: Expression[]
}

export interface CallExpression extends BaseNode {
  kind: "CallExpression"
  callee: Expression
  args: Expression[]
}

export interface FunctionExpression extends BaseNode {
  kind: "FunctionExpression"
  params: Identifier[]
  hasVarArg: boolean
  body: Block
}

export interface TableField extends BaseNode {
  kind: "TableField"
  value: Expression
}

export interface TableKey extends BaseNode {
  kind: "TableKey"
  key: Expression
  value: Expression
}

export interface TableKeyString extends BaseNode {
  kind: "TableKeyString"
  key: Identifier
  value: Expression
}

export type TableEntry = TableField | TableKey | TableKeyString

export interface TableConstructor extends BaseNode {
  kind: "TableConstructor"
  fields: TableEntry[]
}

export type Statement =
  | AssignStatement
  | LocalStatement
  | DoStatement
  | WhileStatement
  | RepeatStatement
  | IfStatement
  | NumericFor
  | GenericFor
  | FunctionDeclaration
  | LocalFunction
  | ReturnStatement
  | BreakStatement
  | ContinueStatement
  | ExpressionStatement

export type Expression =
  | NumberLiteral
  | StringLiteral
  | BooleanLiteral
  | NilLiteral
  | VarArgLiteral
  | Identifier
  | BinaryExpression
  | UnaryExpression
  | IndexExpression
  | FieldExpression
  | MethodCallExpression
  | CallExpression
  | FunctionExpression
  | TableConstructor

export type ASTNode = Statement | Expression | Block

