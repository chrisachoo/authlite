/* eslint-disable no-console */
import fs from "node:fs"

import Database from "better-sqlite3"

const sql = fs.readFileSync(new URL("../migrations/0001_create_tables.sql", import.meta.url), "utf8")
const db = new Database("./zauth.sqlite")
db.exec(sql)
console.log("migrations applied")
db.close()
