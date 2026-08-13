import { expect, test } from "bun:test"
import path from "path"
import { Installer } from "../../src/package/installer"

/**
 * Interpreter selection, and the Windows failure that produced these tests.
 *
 * Measured on a real machine: `python -m venv` exited 0, `ensurepip` genuinely
 * ran, and the environment came out at `<env>/lib/python3.9/site-packages` with
 * `<env>/bin/python.exe` — while every path in `installer.ts` looks under
 * `Scripts\`. `pyvenv.cfg` named the cause outright:
 *
 *     home = C:\msys64\mingw64\bin
 *     version = 3.9.7
 *
 * MSYS2's MinGW Python is a native Windows build that patches `sysconfig` to
 * the POSIX scheme. It was selected because PATH had no `python3.exe` before
 * `C:\msys64\mingw64\bin` — `C:\Python312` ships `python.exe` only — so the
 * `python3 ?? python` preference walked straight past a valid 3.12.
 */

const report = (over: Partial<Installer.Report> = {}): Installer.Report => ({
  exe: "C:\\Python312\\python.exe",
  version: [3, 12],
  platform: "win-amd64",
  purelib: "C:\\Python312\\Lib\\site-packages",
  prefix: "C:\\Python312",
  ...over,
})

const win = process.platform === "win32"

test.if(win)("a real python.org interpreter is accepted", () => {
  expect(Installer.reject(report())).toBeUndefined()
})

test.if(win)("the MSYS2 interpreter that caused this is rejected", () => {
  const why = Installer.reject(
    report({
      exe: "C:\\msys64\\mingw64\\bin\\python3.exe",
      version: [3, 9],
      platform: "mingw_x86_64",
      purelib: "C:\\msys64\\mingw64\\lib\\python3.9\\site-packages",
      prefix: "C:\\msys64\\mingw64",
    }),
  )
  expect(why).toContain("MSYS2")
})

test.if(win)("a POSIX layout is rejected on the scheme alone, whatever the vendor", () => {
  // The vendor check is a nicety for the error message; this is the property
  // that actually breaks the module, so it must stand on its own — otherwise
  // the next cross-built distribution walks through under a different name.
  const why = Installer.reject(report({ purelib: "C:\\Weird\\lib\\python3.12\\site-packages" }))
  expect(why).toContain("POSIX layout")
})

test.if(win)("a non-native platform tag is rejected", () => {
  expect(Installer.reject(report({ platform: "cygwin_x86_64" }))).toContain("not a native win-* build")
})

test.if(!win)("nothing is rejected off Windows, where the POSIX layout is correct", () => {
  expect(
    Installer.reject(report({ platform: "linux-x86_64", purelib: "/usr/lib/python3.12/site-packages" })),
  ).toBeUndefined()
})

test("select() prefers python over python3 on Windows, and the reverse elsewhere", async () => {
  // The single line that chose MSYS2. python.org ships `python.exe` and NO
  // `python3.exe`, so on Windows `python3` resolves to the Store alias or to a
  // POSIX-flavoured distribution nearly by definition. This asserts the source,
  // because the ordering cannot be observed from outside on a Linux CI box.
  const source = await Bun.file(new URL("../../src/package/installer.ts", import.meta.url).pathname).text()
  const body = source.slice(source.indexOf("export async function select()"))
  const order = body.slice(body.indexOf("const names"), body.indexOf("\n", body.indexOf("const names")))
  expect(order.indexOf('"python.exe"')).toBeLessThan(order.indexOf('"python3.exe"'))
  expect(order.indexOf('"python3"')).toBeLessThan(order.indexOf('"python"', order.indexOf('"python3"') + 1))
})

test("select() finds a working interpreter on this machine", async () => {
  const chosen = await Installer.select()
  expect(chosen.binary).toBeTruthy()
  expect(chosen.report?.prefix).toBeTruthy()
})

test("inspect() reports the real interpreter, and undefined for a non-interpreter", async () => {
  const chosen = await Installer.select()
  const found = await Installer.inspect(chosen.binary!)
  expect(found?.version[0]).toBe(3)
  // Debian and Ubuntu use dist-packages, not site-packages, for the system
  // interpreter — the assertion is that a package directory was reported.
  expect(found?.purelib).toMatch(/(site|dist)-packages/)
  // A Store alias exits non-zero; stand in for it with something that exists
  // and is not an interpreter, which is the same observable.
  expect(await Installer.inspect(process.execPath).catch(() => undefined)).toBeUndefined()
})

test("a rejected candidate does not end the search", async () => {
  // `Bun.which` answers once, so the old code stopped at the first hit. Both
  // Windows failures had a bad candidate ahead of a good one — the alias, then
  // MSYS2 — so "reject" has to mean "keep looking" across every PATH entry.
  const source = await Bun.file(new URL("../../src/package/installer.ts", import.meta.url).pathname).text()
  const body = source.slice(
    source.indexOf("export async function select()"),
    source.indexOf("async function registered"),
  )
  expect(body).toContain("continue")
  expect(body).not.toContain("Bun.which")
  // Every rejection is recorded, so the failure can say what it looked at.
  expect(body).toContain("rejected.push")
})

test("locate() searches both layouts, not just this platform's", async () => {
  const source = await Bun.file(new URL("../../src/package/installer.ts", import.meta.url).pathname).text()
  const body = source.slice(source.indexOf("export async function locate"))
  expect(body).toContain('"Scripts", "bin"')
})

test("the error no longer asserts a cause it did not measure", async () => {
  // The claim that a Windows failure "usually means" a Store alias was false on
  // the machine that hit it next, and reading as a finding rather than a guess
  // it sent the investigation to the Settings app for a full cycle.
  const source = await Bun.file(new URL("../../src/package/installer.ts", import.meta.url).pathname).text()
  const create = source.slice(source.indexOf("export async function create"), source.indexOf("const same ="))
  expect(create).not.toContain("App execution aliases")
  expect(create).not.toContain("usually means")
  // What replaced it: the interpreter used, what it reports, where one was
  // actually found, and what landed on disk.
  for (const fact of ["created with:", "an interpreter was found instead at:", "the tree contains:"])
    expect(create).toContain(fact)
})

test("a half-built environment is cleared rather than retried into", async () => {
  // `venv` and `uv` both short-circuit on an existing directory and report
  // success without replacing what is missing, so the first bad creation
  // repeats forever. Observed: "Requirement already satisfied" for pip and
  // setuptools on every retry, and the identical failure after it.
  const source = await Bun.file(new URL("../../src/package/installer.ts", import.meta.url).pathname).text()
  const create = source.slice(source.indexOf("export async function create"), source.indexOf("const same ="))
  const clear = create.indexOf("fs.rm(directory")
  expect(clear).toBeGreaterThan(-1)
  // Before the spawn, or the short-circuit still happens.
  expect(clear).toBeLessThan(create.indexOf("Bun.spawn"))
})

test("interpreter() and locate() agree for an environment built here", async () => {
  // The end-to-end property the Windows machine violated: what the module
  // requires and what creation produces must be the same file.
  const dir = path.join(
    process.env["TMPDIR"] ?? "/tmp",
    `openscience-interp-${process.pid}-${process.hrtime.bigint().toString(36)}`,
  )
  const tool = await Installer.probe(dir)
  await Installer.create(dir, tool)
  try {
    expect(await Installer.locate(dir)).toBe(Installer.interpreter(dir))
    // And it is genuinely rooted in the environment, not the host.
    const check = await Installer.inspect(Installer.interpreter(dir))
    expect(check?.prefix).toBeTruthy()
    // realpath, not just resolve — the same firmlink that broke `same()` in the
    // installer breaks the assertion about it. macOS temp is /var/folders/...,
    // /var is a symlink to /private/var, and Python reports the real path.
    const { realpathSync } = await import("fs")
    expect(realpathSync(check!.prefix)).toBe(realpathSync(dir))
  } finally {
    await (await import("fs/promises")).rm(dir, { recursive: true, force: true }).catch(() => {})
  }
}, 180_000)

test("the base interpreter is only offered to the sandbox that needs it", async () => {
  // Adding it unconditionally broke three green Linux installs:
  //   bwrap: Can't mkdir .../uv/python/cpython-3.12-linux-x86_64-gnu/bin
  // bubblewrap binds the whole filesystem read-only and seatbelt allows reads
  // unless denied, so naming the path there is not redundant, it is a bind whose
  // destination cannot be created under a read-only root. Windows is the only
  // backend where a read has to be granted.
  const dir = path.join(
    process.env["TMPDIR"] ?? "/tmp",
    `openscience-base-${process.pid}-${process.hrtime.bigint().toString(36)}`,
  )
  const tool = await Installer.probe(dir)
  await Installer.create(dir, tool)
  try {
    // venv always writes it, so the value is available on every platform...
    expect(await Installer.base(dir)).toBeTruthy()
    // ...but it is only handed to the sandbox on Windows.
    const offered = await Installer.baseReadable(dir)
    expect(offered).toEqual(process.platform === "win32" ? [(await Installer.base(dir))!] : [])
  } finally {
    await (await import("fs/promises")).rm(dir, { recursive: true, force: true }).catch(() => {})
  }
}, 180_000)
