import * as AST from "../ast/types"

const CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const CHARSET_FULL = CHARSET + "0123456789"

export function generateName(index: number, seed: number): string {
  const rng = mulberry32(seed + index * 2654435761)
  const len = 4 + Math.floor(rng() * 8)
  let name = CHARSET[Math.floor(rng() * CHARSET.length)]
  for (let i = 1; i < len; i++) {
    name += CHARSET_FULL[Math.floor(rng() * CHARSET_FULL.length)]
  }
  return name
}

function mulberry32(seed: number) {
  let s = seed >>> 0
  return () => {
    s += 0x6D2B79F5
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export class Scope {
  private parent: Scope | null
  private locals: Map<string, string> = new Map()
  private globals: Set<string>

  constructor(parent: Scope | null, globals: Set<string>) {
    this.parent = parent
    this.globals = globals
  }

  define(name: string, renamed: string) {
    this.locals.set(name, renamed)
  }

  resolve(name: string): string | null {
    if (this.locals.has(name)) return this.locals.get(name)!
    if (this.parent) return this.parent.resolve(name)
    return null
  }

  isGlobal(name: string): boolean {
    return this.globals.has(name)
  }

  child(): Scope {
    return new Scope(this, this.globals)
  }
}

const ROBLOX_GLOBALS = new Set([
  "game","workspace","script","math","string","table","os","io","debug",
  "coroutine","utf8","bit32","pcall","xpcall","error","assert","type",
  "tostring","tonumber","ipairs","pairs","next","select","unpack",
  "rawget","rawset","rawequal","rawlen","setmetatable","getmetatable",
  "require","load","loadstring","dofile","print","warn","wait","delay",
  "spawn","tick","time","elapsedTime","collectgarbage","gcinfo",
  "Instance","Enum","CFrame","Vector3","Vector2","Color3","UDim2","UDim",
  "Ray","Region3","NumberSequence","ColorSequence","NumberRange",
  "TweenInfo","BrickColor","PhysicalProperties","RaycastParams",
  "OverlapParams","Random","buffer","task","true","false","nil",
  "self","_G","_VERSION","_ENV",
  // executor globals
  "gethwid","request","syn","http","is_synapse_function",
  "identifyexecutor","getgenv","getrenv","getfenv","setfenv",
  "getgc","getupvalues","setupvalue","getupvalue","setreadonly",
  "isreadonly","iscclosure","islclosure","newcclosure","hookfunction",
  "hookmetamethod","getrawmetatable","replicatesignal","fireclickdetector",
  "fireproximityprompt","crypt","rconsoleprint","isfunctionhooked",
  "getnamecallmethod","debug"
])

// ====== RENAMER ======
export class Renamer {
  private nameCounter = 0
  private usedNames = new Set<string>()
  private seed: number

  constructor(seed: number) {
    this.seed = seed
  }

  private nextName(): string {
    let name: string
    do {
      name = generateName(this.nameCounter++, this.seed)
    } while (this.usedNames.has(name) || ROBLOX_GLOBALS.has(name))
    this.usedNames.add(name)
    return name
  }

  rename(block: AST.Block): AST.Block {
    const globalScope = new Scope(null, ROBLOX_GLOBALS)
    return this.renameBlock(block, globalScope)
  }

  private renameBlock(block: AST.Block, scope: Scope): AST.Block {
    const childScope = scope.child()
    return {
      ...block,
      body: block.body.map(s => this.renameStmt(s, childScope))
    }
  }

  private renameStmt(stmt: AST.Statement, scope: Scope): AST.Statement {
    switch (stmt.kind) {
      case "LocalStatement": {
        const values = stmt.values.map(v => this.renameExpr(v, scope))
        const names = stmt.names.map(id => {
          const renamed = this.nextName()
          scope.define(id.name, renamed)
          return { ...id, name: renamed }
        })
        return { ...stmt, names, values }
      }

      case "LocalFunction": {
        const renamed = this.nextName()
        scope.define(stmt.name.name, renamed)
        const fnScope = scope.child()
        const params = this.renameParams(stmt.params, fnScope)
        return {
          ...stmt,
          name: { ...stmt.name, name: renamed },
          params,
          body: this.renameBlock(stmt.body, fnScope)
        }
      }

      case "FunctionDeclaration": {
        const fnScope = scope.child()
        const params = this.renameParams(stmt.params, fnScope)
        return {
          ...stmt,
          name: this.renameExpr(stmt.name, scope),
          params,
          body: this.renameBlock(stmt.body, fnScope)
        }
      }

      case "AssignStatement":
        return {
          ...stmt,
          targets: stmt.targets.map(t => this.renameExpr(t, scope)),
          values: stmt.values.map(v => this.renameExpr(v, scope))
        }

      case "DoStatement":
        return { ...stmt, body: this.renameBlock(stmt.body, scope) }

      case "WhileStatement":
        return {
          ...stmt,
          condition: this.renameExpr(stmt.condition, scope),
          body: this.renameBlock(stmt.body, scope)
        }

      case "RepeatStatement":
        return {
          ...stmt,
          body: this.renameBlock(stmt.body, scope),
          condition: this.renameExpr(stmt.condition, scope)
        }

      case "IfStatement":
        return {
          ...stmt,
          clauses: stmt.clauses.map(c => ({
            ...c,
            condition: c.condition ? this.renameExpr(c.condition, scope) : null,
            body: this.renameBlock(c.body, scope)
          }))
        }

      case "NumericFor": {
        const forScope = scope.child()
        const renamed = this.nextName()
        forScope.define(stmt.name.name, renamed)
        return {
          ...stmt,
          name: { ...stmt.name, name: renamed },
          start: this.renameExpr(stmt.start, scope),
          limit: this.renameExpr(stmt.limit, scope),
          step: stmt.step ? this.renameExpr(stmt.step, scope) : null,
          body: this.renameBlock(stmt.body, forScope)
        }
      }

      case "GenericFor": {
        const forScope = scope.child()
        const iterators = stmt.iterators.map(i => this.renameExpr(i, scope))
        const names = stmt.names.map(id => {
          const renamed = this.nextName()
          forScope.define(id.name, renamed)
          return { ...id, name: renamed }
        })
        return { ...stmt, names, iterators, body: this.renameBlock(stmt.body, forScope) }
      }

      case "ReturnStatement":
        return { ...stmt, values: stmt.values.map(v => this.renameExpr(v, scope)) }

      case "ExpressionStatement":
        return { ...stmt, expression: this.renameExpr(stmt.expression, scope) as any }

      default:
        return stmt
    }
  }

  private renameParams(params: AST.Identifier[], scope: Scope): AST.Identifier[] {
    return params.map(p => {
      if (p.name === "self") return p
      const renamed = this.nextName()
      scope.define(p.name, renamed)
      return { ...p, name: renamed }
    })
  }

  private renameExpr(expr: AST.Expression, scope: Scope): AST.Expression {
    switch (expr.kind) {
      case "Identifier": {
        const resolved = scope.resolve(expr.name)
        if (resolved) return { ...expr, name: resolved }
        return expr
      }

      case "BinaryExpression":
        return {
          ...expr,
          left: this.renameExpr(expr.left, scope),
          right: this.renameExpr(expr.right, scope)
        }

      case "UnaryExpression":
        return { ...expr, operand: this.renameExpr(expr.operand, scope) }

      case "IndexExpression":
        return {
          ...expr,
          object: this.renameExpr(expr.object, scope),
          index: this.renameExpr(expr.index, scope)
        }

      case "FieldExpression":
        return { ...expr, object: this.renameExpr(expr.object, scope) }

      case "CallExpression":
        return {
          ...expr,
          callee: this.renameExpr(expr.callee, scope),
          args: expr.args.map(a => this.renameExpr(a, scope))
        }

      case "MethodCallExpression":
        return {
          ...expr,
          object: this.renameExpr(expr.object, scope),
          args: expr.args.map(a => this.renameExpr(a, scope))
        }

      case "FunctionExpression": {
        const fnScope = scope.child()
        return {
          ...expr,
          params: this.renameParams(expr.params, fnScope),
          body: this.renameBlock(expr.body, fnScope)
        }
      }

      case "TableConstructor":
        return {
          ...expr,
          fields: expr.fields.map(f => {
            switch (f.kind) {
              case "TableField":
                return { ...f, value: this.renameExpr(f.value, scope) }
              case "TableKey":
                return { ...f, key: this.renameExpr(f.key, scope), value: this.renameExpr(f.value, scope) }
              case "TableKeyString":
                return { ...f, value: this.renameExpr(f.value, scope) }
            }
          })
        }

      default:
        return expr
    }
  }
}
