/* eslint-disable no-console */
import fs from "node:fs"

import { createClient } from "@libsql/client"

const sql = fs.readFileSync(new URL("../migrations/0001_create_tables.sql", import.meta.url), "utf8")

;(async () => {
	try {
		const client = createClient({ url: "file:authlite.sqlite" })
		await client.executeMultiple(sql)
		console.log("migrations applied")
		await client.close()
	}
	catch (err) {
		console.error("migration failed", err)
		process.exit(1)
	}
})()
