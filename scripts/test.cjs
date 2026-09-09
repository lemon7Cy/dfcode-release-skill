#!/usr/bin/env node
const fs = require("node:fs")
const path = require("node:path")
const { spawnSync } = require("node:child_process")
const directory = path.resolve(__dirname, "../tests")
const files = fs.readdirSync(directory).filter((name) => name.endsWith(".test.cjs")).sort().map((name) => path.join(directory, name))
const result = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" })
if (result.error) console.error(result.error.message)
process.exitCode = result.status ?? 1
