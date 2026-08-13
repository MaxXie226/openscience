import { expect, test } from "bun:test"
import { AppContainer } from "../../src/sandbox/appcontainer"
import { Sandbox } from "../../src/sandbox/sandbox"

/**
 * What can be tested without Windows.
 *
 * The Win32 calls cannot run here, and pretending otherwise would be worse than
 * admitting it — the probe already measured that sequence on a real machine.
 * What IS testable is everything around them: the spec round trip, the
 * UTF-16 encoding those `...W` entry points require, and the command-line
 * quoting, which is where a silent mistake would hide. `CommandLineToArgvW`
 * re-splits a single string with rules that are neither the shell's nor
 * POSIX's, so a path like `C:\Users\me\My Project\` can quietly change what the
 * child executes rather than failing loudly.
 */

test("the spec survives the base64 round trip Sandbox composes", () => {
  const policy = {
    writable: ["C:\\work\\project"],
    unreadable: ["C:\\Users\\me\\.ssh\\id_rsa"],
    network: "allowlist" as const,
    egress: "openscience-broker-abc",
    profile: "openscience-deadbeef",
  }
  const args = Sandbox.appContainerArgs(policy, ["python.exe", "-u", "k.py"])
  const spec = AppContainer.decode(args[1]!)
  expect(spec.profile).toBe("openscience-deadbeef")
  expect(spec.writable).toEqual(["C:\\work\\project"])
  expect(spec.unreadable).toEqual(["C:\\Users\\me\\.ssh\\id_rsa"])
  expect(spec.network).toBe("allowlist")
  expect(spec.pipe).toBe("openscience-broker-abc")
})

test("a spec with no profile is rejected rather than launched unconfined", () => {
  const blob = Buffer.from(JSON.stringify({ writable: [], unreadable: [], network: "deny" })).toString("base64")
  expect(() => AppContainer.decode(blob)).toThrow("profile")
})

test("wide() produces null-terminated UTF-16LE", () => {
  // Every ...W entry point reads until a null. A missing terminator reads past
  // the buffer; a UTF-8 buffer is silently misinterpreted as UTF-16 pairs.
  const buf = AppContainer.wide("Hi")
  expect([...buf]).toEqual([0x48, 0x00, 0x69, 0x00, 0x00, 0x00])
})

test("readWide reverses wide(), and stops at the terminator", () => {
  const sid = "S-1-15-2-3041870312-880516233"
  const buf = AppContainer.wide(sid)
  // Trailing garbage after the null must be ignored, the way a real SID buffer
  // returned by ConvertSidToStringSid sits inside a larger allocation.
  const padded = Buffer.concat([buf, Buffer.from([0x41, 0x00, 0x42, 0x00])])
  expect(AppContainer.readWide(new Uint8Array(padded))).toBe(sid)
})

test.each([
  ["plain", "python.exe", "python.exe"],
  ["a space", "My Project", '"My Project"'],
  ["a quote", 'say"hi', '"say\\"hi"'],
  // A trailing backslash before the closing quote must be doubled, or it
  // escapes the quote and swallows the next argument.
  ["a trailing backslash with a space", "C:\\My Dir\\", '"C:\\My Dir\\\\"'],
  ["backslashes before a quote", 'a\\\\"b', '"a\\\\\\\\\\"b"'],
  ["backslashes with no quote", "C:\\a\\b", "C:\\a\\b"],
])("quoting %s survives CommandLineToArgvW", (_label, input, expected) => {
  expect(AppContainer.quote(input)).toBe(expected)
})

test("a Windows path with spaces round-trips through the whole command line", () => {
  // The case that matters in practice: the interpreter of a managed environment
  // under a user profile whose name has a space in it.
  const argv = ["C:\\Users\\A B\\.cache\\openscience\\envs\\p\\default\\Scripts\\python.exe", "-u", "C:\\w\\k.py"]
  const line = AppContainer.commandLine(argv)
  expect(line).toContain('"C:\\Users\\A B\\')
  // Re-split the way CommandLineToArgvW would, to prove the quoting is not
  // merely plausible. This mirrors the documented algorithm.
  const parsed: string[] = []
  let current = ""
  let quoted = false
  let slashes = 0
  const flush = () => {
    if (current || quoted) parsed.push(current)
    current = ""
  }
  for (const ch of line) {
    if (ch === "\\") {
      slashes++
      continue
    }
    if (ch === '"') {
      current += "\\".repeat(Math.floor(slashes / 2))
      if (slashes % 2) current += '"'
      else quoted = !quoted
      slashes = 0
      continue
    }
    current += "\\".repeat(slashes)
    slashes = 0
    if (ch === " " && !quoted) {
      flush()
      continue
    }
    current += ch
  }
  current += "\\".repeat(slashes)
  flush()
  expect(parsed).toEqual(argv)
})

test("the launcher refuses to run anywhere but Windows", () => {
  // Guards against a Linux caller reaching FFI that would dlopen kernel32.
  if (process.platform === "win32") return
  expect(() => AppContainer.launch("S-1-15-2-1", ["x"])).toThrow("only runs on Windows")
})

test("the entry point is wired before anything else parses argv", async () => {
  // Same rule the egress shim follows: the launcher must not run startup
  // middleware, which may fetch over a network the container cannot reach.
  const source = await Bun.file(new URL("../../src/index.ts", import.meta.url).pathname).text()
  const at = source.indexOf('process.argv[2] === "__appcontainer-launch"')
  expect(at).toBeGreaterThan(-1)
  expect(at).toBeLessThan(source.indexOf('process.on("unhandledRejection"'))
})

test("describe() reports the appcontainer backend as available", () => {
  // Two commands reading the same backend() disagreed on a real Windows
  // machine: `sandbox status` printed "unavailable - no sandbox backend for
  // platform win32" while `sandbox test` printed "Sandbox self-test
  // (appcontainer)" and ran checks. describe() had a seatbelt/bubblewrap
  // whitelist, so widening the Backend type without widening it here made the
  // new backend fall through to the "none" branch.
  const source = Bun.file(new URL("../../src/sandbox/sandbox.ts", import.meta.url).pathname)
  return source.text().then((text) => {
    const body = text.slice(text.indexOf("export function describe()"), text.indexOf("writable-path assembly"))
    expect(body.includes('b === "appcontainer"')).toBe(true)
    expect(body.includes('tool: "AppContainer"')).toBe(true)
  })
})

test("the self-test proves the child is in a container before judging containment", async () => {
  // A child that never entered the container is indistinguishable from a
  // container with no policy: writes escape and the network works, which is
  // exactly what the first Windows run reported. Reading the child's own token
  // separates "CreateProcess did not confine it" from "it is confined and the
  // policy is wrong" — different bugs, in different files.
  const text = await Bun.file(new URL("../../src/sandbox/sandbox.ts", import.meta.url).pathname).text()
  // Sliced forward from selfTest, not to runAsync: runAsync is defined ABOVE
  // it, so that range was empty and the assertions passed on nothing.
  const body = text.slice(text.indexOf("export async function selfTest"))
  expect(body.includes("whoami /groups")).toBe(true)
  expect(body.includes("S-1-15-2-")).toBe(true)
  // And it must run FIRST, so a false "containment failed" is never reported
  // when the real fault is upstream of the policy.
  expect(body.indexOf("whoami /groups")).toBeLessThan(body.indexOf("write inside the workspace succeeds"))
})
