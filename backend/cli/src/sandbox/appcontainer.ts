/**
 * Windows AppContainer launcher.
 *
 * Linux and macOS both have a wrapper executable — `bwrap`, `sandbox-exec` —
 * so confinement is expressible as an argv. Windows has none: it is applied AT
 * process creation, by passing `SECURITY_CAPABILITIES` through
 * `UpdateProcThreadAttribute` to `CreateProcessW`. So the binary launches
 * itself (`openscience __appcontainer-launch <spec> -- <cmd>`, the pattern
 * `__egress-shim` already established) and this module does the Win32 work.
 *
 * Every call is modelled on `docs/specs/windows-appcontainer-probe.ps1`, which
 * ran this exact sequence on a real Windows 11 machine, unelevated, and
 * measured it working: profile creation, a child launched with zero
 * capabilities, that child unable to reach the network, and two children in the
 * same container able to talk over loopback.
 *
 * The x64 struct offsets below are written out beside the fields they belong
 * to rather than derived. Getting one wrong produces a `CreateProcess` failure
 * that reads as a permissions problem rather than a marshalling one, and that
 * is an expensive hour on a machine none of us can debug interactively.
 *
 * The FFI patterns used here — an out-parameter pointer read back with
 * `read.ptr`, and bytes read at a returned pointer with `toArrayBuffer` — were
 * verified against libc on Linux before being written, because the mechanism
 * is the same and the platform is not available to test on.
 */

export namespace AppContainer {
  /** What the launcher is told to do, carried as one base64 blob through the
   *  command line. Kept in step with `Sandbox.appContainerArgs`. */
  export type Spec = {
    profile: string
    writable: string[]
    /** Paths the child must READ but not write — its interpreter, above all. */
    readable?: string[]
    unreadable: string[]
    network: "deny" | "allowlist" | "allow"
    /** Broker pipe name, when network is "allowlist". */
    pipe?: string
  }

  export function decode(blob: string): Spec {
    const value = JSON.parse(Buffer.from(blob, "base64").toString("utf8")) as Spec
    if (!value?.profile) throw new Error("appcontainer spec carries no profile name")
    if (!Array.isArray(value.writable)) throw new Error("appcontainer spec carries no writable list")
    return value
  }

  /** A null-terminated UTF-16LE buffer, which every `...W` entry point expects.
   *  Bun's FFI has no wide-string type, so strings cross as pointers to buffers
   *  the caller keeps alive for the duration of the call. */
  export function wide(value: string) {
    return Buffer.from(`${value}\0`, "utf16le")
  }

  /** Reads a null-terminated UTF-16LE string out of a byte view. */
  export function readWide(bytes: Uint8Array) {
    const chars: number[] = []
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const code = bytes[i]! | (bytes[i + 1]! << 8)
      if (code === 0) break
      chars.push(code)
    }
    return String.fromCharCode(...chars)
  }

  // ── x64 layouts ───────────────────────────────────────────────────────────
  /** SECURITY_CAPABILITIES { PSID AppContainerSid; PSID_AND_ATTRIBUTES* ; DWORD CapabilityCount; DWORD Reserved } */
  const SECURITY_CAPABILITIES_SIZE = 24
  /** STARTUPINFOW is 104 bytes on x64; STARTUPINFOEXW appends lpAttributeList at 104. */
  const STARTUPINFOEX_SIZE = 112
  const STARTUPINFO_CB_OFFSET = 0
  const STARTUPINFO_FLAGS_OFFSET = 60
  const STARTUPINFO_STDIN_OFFSET = 80
  const STARTUPINFO_STDOUT_OFFSET = 88
  const STARTUPINFO_STDERR_OFFSET = 96
  const STARTUPINFO_ATTRIBUTE_LIST_OFFSET = 104
  const STARTF_USESTDHANDLES = 0x00000100
  const HANDLE_FLAG_INHERIT = 0x00000001
  /** STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE as unsigned. */
  const STD_HANDLES = { input: 0xfffffff6, output: 0xfffffff5, error: 0xfffffff4 }
  /** PROCESS_INFORMATION { HANDLE hProcess; HANDLE hThread; DWORD pid; DWORD tid } */
  const PROCESS_INFORMATION_SIZE = 24
  const PI_PROCESS_OFFSET = 0

  const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
  const EXTENDED_STARTUPINFO_PRESENT = 0x00080000
  /** HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS). The profile is per-user state
   *  that outlives a run by design, so this is the ordinary path. */
  const ALREADY_EXISTS = 0x800700b7
  const INFINITE = 0xffffffff

  type Bound = ReturnType<typeof open>

  /**
   * Bound once per process, and kept.
   *
   * `dlopen` returns a library object that owns the handle; only `.symbols` was
   * being kept, so the object was immediately garbage. Bun closes a library when
   * that object is collected, which would unmap the very code a later call jumps
   * into. `main` binds three times over one launch (ensureProfile, grant, launch)
   * and `launch` opened advapi32 a fourth time, so there was ample opportunity.
   * Caching removes the question entirely rather than reasoning about GC timing.
   */
  let bound: Bound | undefined
  function bind(): Bound {
    bound ??= open()
    return bound
  }

  function open() {
    if (process.platform !== "win32") throw new Error("the AppContainer launcher only runs on Windows")
    // Required lazily and by name so `bun:ffi` never enters the module graph on
    // platforms that cannot call this. These DLLs ship with Windows, so nothing
    // additional is distributed.
    const ffi = require("bun:ffi") as typeof import("bun:ffi")
    const t = ffi.FFIType
    const userenv = ffi.dlopen("userenv.dll", {
      CreateAppContainerProfile: { args: [t.ptr, t.ptr, t.ptr, t.ptr, t.u32, t.ptr], returns: t.i32 },
      DeriveAppContainerSidFromAppContainerName: { args: [t.ptr, t.ptr], returns: t.i32 },
    })
    const advapi = ffi.dlopen("advapi32.dll", {
      ConvertSidToStringSidW: { args: [t.ptr, t.ptr], returns: t.bool },
      ConvertStringSidToSidW: { args: [t.ptr, t.ptr], returns: t.bool },
      FreeSid: { args: [t.ptr], returns: t.ptr },
    })
    const kernel = ffi.dlopen("kernel32.dll", {
        LocalFree: { args: [t.ptr], returns: t.ptr },
        GetLastError: { args: [], returns: t.u32 },
        GetStdHandle: { args: [t.u32], returns: t.ptr },
        SetHandleInformation: { args: [t.ptr, t.u32, t.u32], returns: t.bool },
        InitializeProcThreadAttributeList: { args: [t.ptr, t.u32, t.u32, t.ptr], returns: t.bool },
        UpdateProcThreadAttribute: { args: [t.ptr, t.u32, t.u64, t.ptr, t.u64, t.ptr, t.ptr], returns: t.bool },
        DeleteProcThreadAttributeList: { args: [t.ptr], returns: t.void },
        CreateProcessW: {
          args: [t.ptr, t.ptr, t.ptr, t.ptr, t.bool, t.u32, t.ptr, t.ptr, t.ptr, t.ptr],
          returns: t.bool,
        },
        WaitForSingleObject: { args: [t.ptr, t.u32], returns: t.u32 },
        GetExitCodeProcess: { args: [t.ptr, t.ptr], returns: t.bool },
        CloseHandle: { args: [t.ptr], returns: t.bool },
    })
    // The library objects are returned, not just their symbols, so they stay
    // reachable for the life of the process.
    return { ffi, libs: [userenv, advapi, kernel], userenv: userenv.symbols, advapi: advapi.symbols, kernel: kernel.symbols }
  }

  /**
   * Can this machine actually be confined by us?
   *
   * Loads the DLLs and derives a SID from a name. That is side-effect free — no
   * profile is created — and it exercises the part most likely to be wrong:
   * whether the FFI bindings resolve and the calling convention is right. A
   * broken binding here is the difference between the sandbox being applied and
   * silently not being.
   *
   * It does NOT prove the launch itself works. That is verified at first use,
   * where `launch` throws with the Win32 error rather than degrading quietly.
   * The alternative — assuming Windows can be confined because the platform
   * says win32 — is how you ship a product that claims a sandbox it never
   * applies.
   */
  export function usable(): boolean {
    if (process.platform !== "win32") return false
    try {
      const b = bind()
      const out = new BigUint64Array(1)
      const hr = b.userenv.DeriveAppContainerSidFromAppContainerName(
        b.ffi.ptr(wide("openscience-capability")),
        b.ffi.ptr(out),
      )
      if (hr !== 0) return false
      const sid = b.ffi.read.ptr(b.ffi.ptr(out), 0)
      if (sid) b.advapi.FreeSid(sid as never)
      return true
    } catch {
      return false
    }
  }

  /**
   * Create the profile if absent, and return its package SID as a string.
   *
   * Idempotent by design. The profile is per-user state that outlives a run,
   * and the SID derived from it is what filesystem ACEs and the broker pipe's
   * DACL refer to — recreating it per launch would strand every grant the
   * previous one made. That is why `Sandbox.appContainerProfile` derives a
   * stable name from the workspace rather than generating one.
   */
  export function ensureProfile(name: string, b: Bound = bind()): string {
    const { ffi, userenv, advapi, kernel } = b
    const wname = wide(name)
    const display = wide(name)
    const description = wide("OpenScience sandbox")
    const sidOut = new BigUint64Array(1)

    let hr = userenv.CreateAppContainerProfile(
      ffi.ptr(wname),
      ffi.ptr(display),
      ffi.ptr(description),
      null,
      0,
      ffi.ptr(sidOut),
    )
    if (hr >>> 0 === ALREADY_EXISTS) {
      hr = userenv.DeriveAppContainerSidFromAppContainerName(ffi.ptr(wname), ffi.ptr(sidOut))
      if (hr !== 0) throw new Error(`DeriveAppContainerSidFromAppContainerName failed: 0x${(hr >>> 0).toString(16)}`)
    } else if (hr !== 0) {
      throw new Error(
        `CreateAppContainerProfile failed: 0x${(hr >>> 0).toString(16)}. Windows sandboxing rests on this call; ` +
          `without it nothing can be confined. It is expected to succeed for a standard user, unelevated.`,
      )
    }

    const sid = ffi.read.ptr(ffi.ptr(sidOut), 0)
    const strOut = new BigUint64Array(1)
    if (!advapi.ConvertSidToStringSidW(sid as never, ffi.ptr(strOut))) {
      throw new Error(`ConvertSidToStringSid failed: Win32 ${kernel.GetLastError()}`)
    }
    const strPtr = ffi.read.ptr(ffi.ptr(strOut), 0)
    // A package SID is well under 512 UTF-16 code units; readWide stops at the
    // first null either way.
    const text = readWide(new Uint8Array(ffi.toArrayBuffer(strPtr as never, 0, 1024)))
    kernel.LocalFree(strPtr as never)
    advapi.FreeSid(sid as never)
    return text
  }

  /**
   * Grant the package SID access to paths the sandboxed process must write.
   *
   * An AppContainer reaches nothing outside its own package folders, so the
   * workspace has to be granted explicitly. `icacls` rather than
   * `SetNamedSecurityInfo` through FFI: it ships with Windows, takes a SID
   * directly in the `*S-1-...` form, and a shelled command that fails is far
   * easier to diagnose than a marshalled ACL that silently grants the wrong
   * thing. The probe measured that the package's OWN temp is already writable
   * with no grant, so only caller-supplied paths are touched.
   *
   * Returns the paths it could not grant rather than throwing: a workspace that
   * is partly ungrantable should still launch and fail visibly at the write,
   * not vanish behind a launcher error.
   */
  export function grant(sid: string, writable: string[], readable: string[] = []) {
    const failures: string[] = []
    // Read-and-execute, not full control, for the read set. The interpreter has
    // to be EXECUTABLE as well as readable — a venv's Scripts\python.exe is a
    // redirector that starts the base interpreter — so plain (R) is not enough,
    // and (F) would hand the sandbox write access to the Python installation it
    // is supposed to be confined away from.
    const rights: Array<[string[], string]> = [
      [writable, "(OI)(CI)(F)"],
      [readable.filter((p) => !writable.includes(p)), "(OI)(CI)(RX)"],
    ]
    for (const [paths, mask] of rights)
      for (const target of paths) {
        const proc = Bun.spawnSync(["icacls.exe", target, "/grant", `*${sid}:${mask}`, "/Q"], {
          stdout: "ignore",
          stderr: "pipe",
        })
        if (proc.exitCode !== 0) failures.push(`${target}: ${proc.stderr.toString().trim() || `exit ${proc.exitCode}`}`)
      }
    return failures
  }

  /**
   * Quote one argument the way `CommandLineToArgvW` will parse it back.
   *
   * Windows has no argv: `CreateProcess` takes a single string and the child
   * re-splits it. The rules are neither the shell's nor POSIX's — backslashes
   * are literal except immediately before a quote, where they double. Getting
   * this wrong on a path like `C:\Users\me\My Project\` silently changes what
   * the child runs, which is the whole reason the sandbox spec travels as
   * base64 rather than as flags.
   */
  export function quote(value: string) {
    if (value.length && !/[\s"]/.test(value)) return value
    let out = '"'
    let slashes = 0
    for (const ch of value) {
      if (ch === "\\") {
        slashes++
        continue
      }
      if (ch === '"') {
        out += "\\".repeat(slashes * 2 + 1) + '"'
        slashes = 0
        continue
      }
      out += "\\".repeat(slashes) + ch
      slashes = 0
    }
    return `${out}${"\\".repeat(slashes * 2)}"`
  }

  export function commandLine(argv: string[]) {
    return argv.map(quote).join(" ")
  }

  /**
   * Launch `argv` inside the AppContainer for `sid`, with NO capabilities, and
   * return its exit code.
   *
   * Zero capabilities is the entire point: no `internetClient`, nothing. The
   * probe measured that such a container reaches no external host, no host
   * loopback listener, and resolves no DNS, while remaining able to talk to
   * another process in the same container over loopback — which is what makes
   * the shim model viable here.
   */
  export function launch(sid: string, argv: string[], b: Bound = bind()): number {
    const { ffi, advapi, kernel } = b
    // Set OPENSCIENCE_SANDBOX_DEBUG=1 to dump every intermediate value.
    //
    // `sandbox test` has now proved the child runs UNCONFINED: CreateProcess
    // succeeds, the command executes, and the token carries no package SID. The
    // probe ran this same sequence successfully in PowerShell on the same
    // machine, so the difference is in what we hand the kernel, not in what the
    // kernel supports. Guessing at that across a rebuild cycle each time has
    // been the expensive part; this makes one run answer it.
    const debug = process.env["OPENSCIENCE_SANDBOX_DEBUG"] === "1"
    const say = (line: string) => {
      if (debug) process.stderr.write(`openscience[appcontainer] ${line}\n`)
    }
    const bytes = (view: Uint8Array) => Buffer.from(view).toString("hex")
    const keep: unknown[] = []

    const sidBuf = new BigUint64Array(1)
    // ConvertStringSidToSidW comes from the cached binding now. Opening
    // advapi32 a second time here left a library object nothing referenced.
    if (!advapi.ConvertStringSidToSidW(ffi.ptr(wide(sid)), ffi.ptr(sidBuf))) {
      throw new Error(`ConvertStringSidToSid failed for ${sid}: Win32 ${kernel.GetLastError()}`)
    }
    const sidPtr = ffi.read.ptr(ffi.ptr(sidBuf), 0)
    say(`sid ${sid} -> 0x${(sidPtr as number).toString(16)}`)

    // Size the attribute list, then allocate and initialise it. The first call
    // is expected to fail with ERROR_INSUFFICIENT_BUFFER; only the size matters.
    const sizeOut = new BigUint64Array(1)
    kernel.InitializeProcThreadAttributeList(null, 1, 0, ffi.ptr(sizeOut))
    const listSize = Number(sizeOut[0]!)
    say(`attribute list size ${listSize}`)
    if (!listSize) throw new Error("InitializeProcThreadAttributeList reported a zero-length attribute list")
    const attributes = new Uint8Array(listSize)
    if (!kernel.InitializeProcThreadAttributeList(ffi.ptr(attributes), 1, 0, ffi.ptr(sizeOut))) {
      throw new Error(`InitializeProcThreadAttributeList failed: Win32 ${kernel.GetLastError()}`)
    }

    const capabilities = new Uint8Array(SECURITY_CAPABILITIES_SIZE)
    new DataView(capabilities.buffer).setBigUint64(0, BigInt(sidPtr as number), true)
    // Capabilities pointer stays null and CapabilityCount stays 0 — that is the
    // containment.
    //
    // These two buffers must outlive the call: UpdateProcThreadAttribute stores
    // a POINTER to `capabilities` inside `attributes`, and does not copy it, so
    // the value has to still be there when CreateProcess reads the list. C# uses
    // AllocHGlobal for exactly this reason. Holding both in `keep` makes the
    // lifetime explicit rather than relying on them merely still being in scope.
    keep.push(attributes, capabilities, sidBuf)
    say(`capabilities ${bytes(capabilities)}`)
    say(`attributes at 0x${(ffi.ptr(attributes) as number).toString(16)}`)

    if (
      !kernel.UpdateProcThreadAttribute(
        ffi.ptr(attributes),
        0,
        BigInt(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES) as never,
        ffi.ptr(capabilities),
        BigInt(SECURITY_CAPABILITIES_SIZE) as never,
        null,
        null,
      )
    ) {
      throw new Error(`UpdateProcThreadAttribute failed: Win32 ${kernel.GetLastError()}`)
    }

    const startup = new Uint8Array(STARTUPINFOEX_SIZE)
    const startupView = new DataView(startup.buffer)
    startupView.setUint32(STARTUPINFO_CB_OFFSET, STARTUPINFOEX_SIZE, true)
    startupView.setBigUint64(STARTUPINFO_ATTRIBUTE_LIST_OFFSET, BigInt(ffi.ptr(attributes)), true)

    // Hand the child our own std handles, and let it inherit them.
    //
    // `bInheritHandles: false` was silently fatal in a way that looked exactly
    // like a containment failure. The launcher is spawned with its stdout on a
    // PIPE, and a child inheriting nothing has nowhere to write, so every
    // sandboxed command produced empty output. The first Windows self-test read
    // that empty stdout, found no package SID in it, and reported the container
    // as not applied — when the token may have been correct and merely
    // unreadable. Two different bugs with one observable, which is precisely
    // what the token check was added to prevent, so the check now reports the
    // child's exit status and stderr as well.
    //
    // This is not a test-only concern. Every sandboxed command's output crosses
    // this boundary: pip's progress, a bash tool's result, a kernel's stream.
    const inherit = (id: number) => {
      const h = kernel.GetStdHandle(id) as number
      // GetStdHandle answers 0 for "none" and INVALID_HANDLE_VALUE for failure;
      // the latter is -1, which arrives here as an unsafe integer.
      if (!Number.isSafeInteger(h) || h <= 0) return 0n
      // Inheritance is a property of the handle in THIS process, and the ones
      // we were given are not necessarily marked for it.
      kernel.SetHandleInformation(h as never, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
      return BigInt(h)
    }
    const stdout = inherit(STD_HANDLES.output)
    const stderr = inherit(STD_HANDLES.error)
    // Only claim the handles when there is something to claim: with the flag
    // set and a null handle the child gets no stdout at all, which is the very
    // failure this replaces. Without it the child attaches to our console,
    // which is the right fallback when we have one.
    if (stdout && stderr) {
      startupView.setUint32(STARTUPINFO_FLAGS_OFFSET, STARTF_USESTDHANDLES, true)
      startupView.setBigUint64(STARTUPINFO_STDIN_OFFSET, inherit(STD_HANDLES.input), true)
      startupView.setBigUint64(STARTUPINFO_STDOUT_OFFSET, stdout, true)
      startupView.setBigUint64(STARTUPINFO_STDERR_OFFSET, stderr, true)
    }

    const info = new Uint8Array(PROCESS_INFORMATION_SIZE)
    // Mutable: CreateProcessW may write into lpCommandLine.
    const line = wide(commandLine(argv))
    keep.push(startup, info, line)
    // The whole STARTUPINFOEX as the kernel will read it. cb must be 0x70 (112)
    // in the first four bytes, and the attribute-list pointer must be non-zero
    // at offset 104 — if either is wrong, CreateProcess ignores the list and
    // succeeds anyway, which is precisely the failure being chased.
    say(`startupinfoex ${bytes(startup)}`)
    say(`  cb=${new DataView(startup.buffer).getUint32(STARTUPINFO_CB_OFFSET, true)} (expect ${STARTUPINFOEX_SIZE})`)
    say(
      `  lpAttributeList=0x${new DataView(startup.buffer).getBigUint64(STARTUPINFO_ATTRIBUTE_LIST_OFFSET, true).toString(16)}`,
    )
    say(`commandline ${commandLine(argv)}`)

    const ok = kernel.CreateProcessW(
      null,
      ffi.ptr(line),
      null,
      null,
      true,
      // No CREATE_UNICODE_ENVIRONMENT: lpEnvironment below is null, so the child
      // inherits ours and the flag would describe a block never supplied.
      EXTENDED_STARTUPINFO_PRESENT,
      null,
      null,
      ffi.ptr(startup),
      ffi.ptr(info),
    )
    say(`CreateProcessW -> ${ok} (Win32 ${ok ? 0 : kernel.GetLastError()})`)
    // Only now is the attribute list dead. Referenced here so nothing above can
    // be considered unreachable while the kernel still holds pointers into it.
    kernel.DeleteProcThreadAttributeList(ffi.ptr(attributes))
    keep.length = 0
    if (!ok) {
      throw new Error(
        `CreateProcess into the AppContainer failed: Win32 ${kernel.GetLastError()}. ` +
          `Win32 5 is access denied; 2 means the executable was not found; ` +
          // 203 was the one actually hit on a real machine, and it was not in
          // this list, so the number carried no meaning at the point of failure.
          // lpApplicationName is null, so Windows resolves argv[0] itself and
          // needs an environment to do it in.
          `203 is ERROR_ENVVAR_NOT_FOUND, which points at the environment this ` +
          `process was given rather than at the command.`,
      )
    }

    const handle = ffi.read.ptr(ffi.ptr(info), PI_PROCESS_OFFSET)
    kernel.WaitForSingleObject(handle as never, INFINITE)
    const codeOut = new Uint32Array(1)
    kernel.GetExitCodeProcess(handle as never, ffi.ptr(codeOut))
    kernel.CloseHandle(handle as never)
    return codeOut[0]!
  }

  /**
   * The `__appcontainer-launch` entry point: decode the spec, ensure the
   * profile, grant the workspace, run the real command, propagate its exit
   * code.
   *
   * Grant failures are reported on stderr rather than thrown. The command
   * should still run and fail visibly at the write it cannot make, rather than
   * disappearing behind a launcher error that says nothing about what the user
   * actually asked for.
   */
  export async function main(blob: string, argv: string[]): Promise<number> {
    const spec = decode(blob)
    const sid = ensureProfile(spec.profile)
    const failures = grant(sid, spec.writable, spec.readable ?? [])
    for (const failure of failures) process.stderr.write(`openscience: could not grant sandbox access to ${failure}\n`)
    return launch(sid, argv)
  }
}
