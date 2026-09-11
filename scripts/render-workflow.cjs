#!/usr/bin/env node
"use strict"

const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { loadConfig, normalizeConfig } = require("./config.cjs")

const TEMPLATE = path.resolve(__dirname, "../assets/desktop-unsigned.yml")

function renderWorkflow(rawConfig) {
  const config = normalizeConfig(rawConfig)
  const replacements = {
    RUN_NAME: `DFCode unsigned v${config.version}`,
    VERSION: config.version,
    STUDIO_REPOSITORY: config.studioRepository,
    STUDIO_COMMIT: config.studioCommit,
    ENGINE_REPOSITORY: config.engineRepository,
    ENGINE_COMMIT: config.engineCommit,
    ENGINE_VERSION: config.engineVersion,
    BUILD_REPOSITORY: config.buildRepository,
    CHANNEL: config.channel,
    UPDATE_BASE_URL: config.updateBaseUrl,
    RELEASE_NOTES: `.release-handoff/docs/releases/studio-v${config.version}.md`,
    OTA_NOTES: `.release-handoff/docs/releases/studio-v${config.version}-ota.md`,
  }
  for (const [name, value] of Object.entries(replacements)) {
    assert(typeof value === "string" && !value.includes("${{"), `Workflow expression is not allowed in ${name}`)
  }
  const used = new Set()
  const result = fs.readFileSync(TEMPLATE, "utf8").replaceAll("\r\n", "\n").replace(/@@([A-Z_]+)@@/g, (_, name) => {
    assert(Object.hasOwn(replacements, name), `Unknown workflow template field: ${name}`)
    used.add(name)
    return JSON.stringify(replacements[name])
  })
  assert(!result.includes("@@"), "Unresolved workflow template token")
  for (const name of Object.keys(replacements)) assert(used.has(name), `Unused workflow field: ${name}`)
  return result
}

function writeWorkflow(config, output) {
  const rendered = renderWorkflow(config)
  const target = path.resolve(output)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, rendered, { flag: "wx" })
  return target
}

function main(args) {
  const options = {}
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index]
    assert(["--config", "--output"].includes(key) && !Object.hasOwn(options, key), "Usage: render-workflow.cjs --config PATH --output PATH")
    assert(args[index + 1] && !args[index + 1].startsWith("--"), `Missing value for ${key}`)
    options[key] = args[index + 1]
  }
  assert(options["--config"] && options["--output"], "Usage: render-workflow.cjs --config PATH --output PATH")
  console.log(writeWorkflow(loadConfig(options["--config"]), options["--output"]))
}

if (require.main === module) {
  try { main(process.argv.slice(2)) } catch (error) { console.error(error.message); process.exitCode = 1 }
}

module.exports = { renderWorkflow, writeWorkflow }
