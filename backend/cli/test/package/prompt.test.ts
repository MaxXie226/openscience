import { expect, test } from "bun:test"
import { PackagePrompt } from "../../src/package/prompt"
import { SystemPrompt } from "../../src/session/system"

test("packages() returns the capability block, shaped like compute()", async () => {
  const block = await SystemPrompt.packages({ environments: [] })
  expect(block).toHaveLength(1)
  expect(block[0]).toContain("<package-capability>")
  expect(block[0]).toContain("</package-capability>")
})

test("an empty inventory tells the agent the first install creates one", () => {
  const rendered = PackagePrompt.render({ environments: [] })
  expect(rendered).toContain("No environments exist yet")
})

test("an inventory lists requested packages only, with a dependency count", () => {
  const rendered = PackagePrompt.render({
    environments: [{ name: "default", language: "python", requested: ["numpy", "pandas"], total: 168, busy: false }],
  })
  expect(rendered).toContain("default (python): numpy, pandas (+166 deps)")
  // The resolved closure is dominated by libgcc/harfbuzz/qt6-main and would
  // bury the contract in font libraries.
  expect(rendered).not.toContain("libgcc")
})

test("a busy environment is flagged so the agent does not execute into it", () => {
  const rendered = PackagePrompt.render({
    environments: [{ name: "default", language: "python", requested: [], total: 0, busy: true }],
  })
  expect(rendered).toContain("INSTALL IN PROGRESS")
})

test("the contract promises refusal, not a missing network", () => {
  const rendered = PackagePrompt.render({ environments: [] })
  // The old wording said "the agent shell has no network", which the allowlist
  // proxy made false — and it implied the venv-in-workspace route was
  // impossible when it is exactly what works.
  expect(rendered).not.toContain("no network")
  expect(rendered).toContain("refused")
  expect(rendered).toContain("virtualenv you create yourself")
})

test("the injection is unconditional, beside compute()", async () => {
  // The load-bearing mechanism is that this reaches EVERY request for EVERY
  // agent — not a skill override, which only reaches a skill's front page and
  // never its reference files or a third-party skill cloned from GitHub.
  const source = await Bun.file(new URL("../../src/session/prompt.ts", import.meta.url).pathname).text()
  // A boolean, not toContain(source): a failing toContain prints the whole
  // 86KB file into the runner output and buries every other result.
  expect(source.includes("await SystemPrompt.packages()")).toBe(true)
})
