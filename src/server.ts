import express from "express"
import path from "path"
import { parseSource } from "./index"

const app = express()
const PORT = process.env.PORT || 3000

app.use(express.json({ limit: "10mb" }))
app.use(express.static(path.join(__dirname, "../../public")))

app.post("/api/obfuscate", (req, res) => {
  const { code, options } = req.body
  if (!code || typeof code !== "string") {
    return res.status(400).json({ error: "Missing code" })
  }

  const { ast, errors } = parseSource(code)

  if (errors.length > 0) {
    return res.json({ ok: false, errors })
  }

  return res.json({ ok: true, output: code, ast })
})

app.get("/api/status", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), version: "1.0.0" })
})

app.listen(PORT, () => {
  console.log(`✅ Candy Obfuscator running on port ${PORT}`)
})

