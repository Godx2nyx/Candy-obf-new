import express from "express"
import path from "path"
import { Lexer } from "./lexer/lexer"
import { parse } from "./parser/parser"
import { obfuscate, ObfuscateOptions } from "./obfuscator/index"

const app = express()
const PORT = process.env.PORT || 3000

app.use(express.json({ limit: "10mb" }))
app.use(express.static(path.join(__dirname, "../../public")))

app.post("/api/obfuscate", (req, res) => {
  const { code, options } = req.body

  if (!code || typeof code !== "string") {
    return res.status(400).json({ ok: false, error: "Missing code" })
  }

  try {
    const lexer = new Lexer(code)
    const tokens = lexer.tokenize()
    const lexErrors = lexer.getErrors()

    if (lexErrors.length > 0) {
      return res.json({ ok: false, errors: lexErrors })
    }

    const { ast, errors: parseErrors } = parse(tokens)

    if (parseErrors.length > 0) {
      return res.json({ ok: false, errors: parseErrors })
    }

    const obfOpts: ObfuscateOptions = {
      rename:        options?.rename        !== false,
      encodeStrings: options?.encodeStrings !== false,
      minify:        options?.minify        === true,
      vmType:        options?.vmType        ?? "register",
      vmLevel:       options?.vmLevel       ?? "max",
      seed:          options?.seed
    }

    const output = obfuscate(ast, obfOpts)

    return res.json({ ok: true, output })

  } catch (err: any) {
    console.error("[obfuscate error]", err)
    return res.status(500).json({ ok: false, error: err.message || "Internal error" })
  }
})

app.get("/api/status", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), version: "1.0.0" })
})

app.get("/ping", (req, res) => res.send("pong"))

app.listen(PORT, () => {
  console.log(`Candy Obfuscator running on port ${PORT}`)
})
