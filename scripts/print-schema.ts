/* Simple CLI to print schema SQL (copy/paste into your app).
   Intentionally minimal to keep package light. */
import * as fs from "node:fs"
import * as path from "node:path"

const schemaPath = path.resolve(__dirname, "../src/db/schema.ts")
const schema = fs.readFileSync(schemaPath, "utf8")
process.stdout.write(schema)
