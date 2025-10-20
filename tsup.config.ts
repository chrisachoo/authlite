import { defineConfig } from "tsup"

export default defineConfig({
	clean: true,
	dts: true,
	entry: ["src/index.ts"],
	external: ["better-sqlite3", "drizzle-orm", "ioredis", "@node-rs/argon2"],
	format: ["esm", "cjs"],
	minify: false,
	sourcemap: true
})
