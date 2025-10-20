import { defineConfig } from "tsup"

export default defineConfig({
	clean: true,
	dts: true,
	entry: {
		"drizzle-sqlite": "src/adapters/drizzle-sqlite.ts",
		"index": "src/index.ts",
		"types": "src/types.entry.ts"
	},
	external: ["better-sqlite3", "drizzle-orm", "ioredis", "@node-rs/argon2"],
	format: ["esm", "cjs"],
	minify: false,
	sourcemap: true
})
