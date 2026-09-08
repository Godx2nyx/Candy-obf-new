import express from "express"
import path from "path"
import { Lexer } from "./lexer/lexer"
import { parse } from "./parser/parser"
import { obfuscate, ObfuscateOptions } from "./obfuscator/index"

const app = express()
const PORT = process.env.PORT || 3000

app.use(express.json({ limit: "10mb" }))
app.use(express.static(path.join(__dirname, "../public")))

app.post("/api/obfuscate", (req, res) => {
  const { code, options = {} } = req.body ?? {}

  if (typeof code !== "string" || !code.trim()) {
    return res.status(400).json({
      ok: false,
      error: "Missing code"
    })
  }

  try {
    const lexer = new Lexer(code)
    const tokens = lexer.tokenize()
    const lexErrors = lexer.getErrors()

    if (lexErrors.length > 0) {
      return res.json({
        ok: false,
        errors: lexErrors
      })
    }

    const { ast, errors: parseErrors } = parse(tokens)

    if (parseErrors.length > 0) {
      return res.json({
        ok: false,
        errors: parseErrors
      })
    }

    /*
     * Max preset is intentionally controlled by the server.
     * The browser cannot downgrade the VM level.
     */
    const obfOpts: ObfuscateOptions = {
      rename: true,
      encodeStrings: true,
      minify: true,

      vmType: "register",
      vmLevel: "max",

      seed:
        Number.isInteger(options.seed)
          ? (options.seed >>> 0)
          : undefined
    }

    const output = obfuscate(ast, obfOpts)

    return res.json({
      ok: true,
      output
    })
  } catch (err: any) {
    console.error("[obfuscate error]", err)

    return res.status(500).json({
      ok: false,
      error: err?.message || "Internal error"
    })
  }
})

app.get("/api/status", (_req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    version: "1.0.0"
  })
})

app.get("/ping", (_req, res) => {
  res.send("pong")
})

app.listen(PORT, () => {
  console.log(`Candy Obfuscator running on port ${PORT}`)
})
