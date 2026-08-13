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

test("the child inherits the launcher's std handles", async () => {
  // `bInheritHandles: false` with no STARTF_USESTDHANDLES was silently fatal:
  // the launcher runs with its stdout on a pipe, so a child inheriting nothing
  // had nowhere to write and EVERY sandboxed command came back empty. The first
  // Windows self-test read that empty stdout, found no package SID, and
  // reported the container as not applied — a launcher bug wearing a policy
  // bug's clothes. Not test-only: pip progress and every tool result cross here.
  const source = await Bun.file(new URL("../../src/sandbox/appcontainer.ts", import.meta.url).pathname).text()
  const body = source.slice(source.indexOf("export function launch"))
  // bInheritHandles is the last argument before the creation flags. Slicing to
  // the first ")" would land inside `ffi.ptr(line)`, so bound it on the flags.
  const create = body.slice(body.indexOf("kernel.CreateProcessW"), body.indexOf("EXTENDED_STARTUPINFO_PRESENT |"))
  expect(create).toContain("true,")
  expect(create).not.toContain("false,")
  expect(body).toContain("STARTF_USESTDHANDLES")
  // Handles we were given are not necessarily marked inheritable in us.
  expect(body).toContain("SetHandleInformation")
  // The flag must not be set without handles behind it, or the child gets no
  // stdout at all — the same failure by another route.
  expect(body.indexOf("if (stdout && stderr)")).toBeLessThan(body.indexOf("STARTF_USESTDHANDLES, true"))
})

test("the containment check distinguishes a silent child from an uncontained one", async () => {
  // Same defect the installer's error message had: asserting one cause when
  // two produce the identical observable.
  const text = await Bun.file(new URL("../../src/sandbox/sandbox.ts", import.meta.url).pathname).text()
  const body = text.slice(text.indexOf("export async function selfTest"))
  const check = body.slice(body.indexOf("whoami /groups"), body.indexOf("write inside the workspace succeeds"))
  expect(check).toContain("produced no output at all")
  expect(check).toContain("SECURITY_CAPABILITIES did not take effect")
  // The child's own stderr is the launcher's error message, and it names which
  // Win32 call failed. Dropping it was what made the first failure unreadable.
  expect(check).toContain("token.stderr")
  // A Windows console decodes our UTF-8 as its OEM code page, so what this
  // check PRINTS stays ASCII. Comments are not printed, so judge only the
  // string literals.
  const printed = check
    .split("\n")
    .filter((l) => !l.trimStart().startsWith("//"))
    .join("\n")
  // eslint-disable-next-line no-control-regex
  expect(printed).not.toMatch(/[^\x00-\x7F]/)
})

test("the CreateProcess failure explains 203, the code a real machine returned", async () => {
  // The hint listed Win32 5 and 2. The machine returned 203, so at the moment of
  // failure the number carried no meaning at all. 203 is ERROR_ENVVAR_NOT_FOUND,
  // which points at the environment rather than the command — lpApplicationName
  // is null, so Windows resolves argv[0] itself and needs an environment to do
  // it in.
  const source = await Bun.file(new URL("../../src/sandbox/appcontainer.ts", import.meta.url).pathname).text()
  expect(source).toContain("203 is ERROR_ENVVAR_NOT_FOUND")
  // Comments are not code: this asserts the flag is not USED, and the comment
  // explaining why it was removed must not trip it.
  const code = source
    .split("\n")
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join("\n")
  // And the flag that described an environment block we never supply is gone.
  expect(code).not.toContain("CREATE_UNICODE_ENVIRONMENT")
})

test("readable paths reach the launcher and are granted read+execute, not full control", async () => {
  // The gap that made Windows look like a broken machine. bubblewrap binds the
  // whole filesystem read-only and seatbelt allows reads unless denied, so
  // `readable` is a no-op on both and its absence here went unnoticed. An
  // AppContainer reaches nothing whose ACL does not name its package SID, so
  // dropping it left the kernel unable to read its own interpreter: `dir`
  // returned "Access is denied" and the venv redirector reported
  // `No Python at '...'` for a Python that was installed and working.
  const args = Sandbox.appContainerArgs(
    {
      writable: ["C:\\work\\project"],
      readable: ["C:\\Python312"],
      unreadable: [],
      network: "deny" as const,
      profile: "openscience-deadbeef",
    },
    ["python.exe"],
  )
  expect(AppContainer.decode(args[1]!).readable).toEqual(["C:\\Python312"])

  const source = await Bun.file(new URL("../../src/sandbox/appcontainer.ts", import.meta.url).pathname).text()
  const body = source.slice(source.indexOf("export function grant"), source.indexOf("export function quote"))
  // Read AND execute: the interpreter must be runnable, so plain (R) is not
  // enough. Never (F) for the read set — that would hand a sandboxed process
  // write access to the Python installation it is confined away from.
  expect(body).toContain("(OI)(CI)(RX)")
  expect(body).toContain("(OI)(CI)(F)")
  expect(body.indexOf("(OI)(CI)(F)")).toBeLessThan(body.indexOf("(OI)(CI)(RX)"))
})

test("a path that is already writable is not re-granted as read-only", () => {
  // Two ACEs for one SID on one path is not wrong, but the weaker one is noise
  // in `icacls` output and makes a real grant failure harder to spot.
  const args = Sandbox.appContainerArgs(
    {
      writable: ["C:\\work\\project"],
      readable: ["C:\\work\\project", "C:\\Python312"],
      unreadable: [],
      network: "deny" as const,
      profile: "p",
    },
    ["x.exe"],
  )
  const spec = AppContainer.decode(args[1]!)
  expect(spec.readable).toContain("C:\\work\\project")
  // The de-duplication is in grant(), which is where both lists are known.
  expect(Bun.file(new URL("../../src/sandbox/appcontainer.ts", import.meta.url).pathname).text()).resolves.toContain(
    "readable.filter((p) => !writable.includes(p))",
  )
})

test("the launcher can dump every value CreateProcess is given", async () => {
  // `sandbox test` proved the child runs unconfined: CreateProcess succeeds, the
  // command executes, and the token carries no package SID. The probe ran this
  // same sequence successfully in PowerShell on the same machine, so the fault
  // is in what we hand the kernel. Each guess at that cost a full rebuild cycle,
  // which is why the values are now dumpable in one run.
  const source = await Bun.file(new URL("../../src/sandbox/appcontainer.ts", import.meta.url).pathname).text()
  const body = source.slice(source.indexOf("export function launch"))
  expect(body).toContain("OPENSCIENCE_SANDBOX_DEBUG")
  // The four values that can each independently cause a silent no-op: the SID,
  // the struct handed to UpdateProcThreadAttribute, cb, and the list pointer.
  for (const value of ["capabilities ", "startupinfoex ", "cb=", "lpAttributeList=0x"]) expect(body).toContain(value)
})

test("the FFI bindings are opened once and held", async () => {
  // dlopen returns a library object that owns the handle; keeping only .symbols
  // left it garbage, and Bun closes a library when that object is collected —
  // unmapping code a later call jumps into. main() bound three times per launch
  // and launch() opened advapi32 a fourth.
  const source = await Bun.file(new URL("../../src/sandbox/appcontainer.ts", import.meta.url).pathname).text()
  expect(source).toContain("libs: [userenv, advapi, kernel]")
  expect(source).toContain("bound ??= open()")
  // advapi32 must not be reopened inside launch().
  const body = source.slice(source.indexOf("export function launch"))
  expect(body).not.toContain("dlopen")
})
