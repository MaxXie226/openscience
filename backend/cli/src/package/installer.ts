import fs from "fs/promises"
import path from "path"
import { Config } from "../config/config"
import { EgressRuntime } from "../sandbox/egress-runtime"
import { Sandbox } from "../sandbox/sandbox"

/**
 * The installer ladder and the sandboxed run.
 *
 * The install runs in the SAME sandbox as the kernel, not a second more
 * permissive one. Earlier drafts specified a separate network-enabled install
 * sandbox because the kernel's was network-denied; the allowlist proxy removed
 * that asymmetry, so the only differences are what is writable — the
 * environment directory and a package cache inside it.
 *
 * uv is a fast path, never a requirement: `python3 -m venv` bootstraps pip
 * offline from the interpreter's bundled `ensurepip` wheel, verified inside
 * `--unshare-net` on a host whose `python3` has no pip at all. Never
 * auto-download uv — probe, use if present, throw a remedy if not. House
 * precedent: `compute/modal/volume.ts:112-116`.
 */
export namespace Installer {
  export type Tool = { kind: "existing" | "uv" | "venv"; binary: string }

  const bindir = process.platform === "win32" ? "Scripts" : "bin"
  const exe = process.platform === "win32" ? ".exe" : ""

  /** PEP 503 normalisation, matching `Requirement.parse`. Both sides of an
   *  additivity comparison have to agree or an upgrade looks like an addition. */
  const normalise = (value: string) => value.replace(/[-_.]+/g, "-").toLowerCase()

  /** The environment's own interpreter — what kernels bind to, and what every
   *  install and verification runs through. */
  export function interpreter(directory: string) {
    return path.join(directory, bindir, `python${exe}`)
  }

  /**
   * The environment's R library directory — R's equivalent of the interpreter
   * binding, since R has no per-environment binary to point at. Reached through
   * `R_LIBS_USER`, which is already in the kernel env allowlist.
   *
   * Kept beside `interpreter` rather than in the R installer so both language
   * backends derive their paths from one place; a kernel needs this before any
   * R install has ever run.
   */
  export function rlibrary(directory: string) {
    return path.join(directory, "rlibs")
  }

  /**
   * The ladder, in order: an existing environment wins over any tool, then uv,
   * then venv, then a remedy.
   *
   * `available` exists so the uv/venv branches are testable on a machine that
   * has only one of them; real callers omit it and get a live probe.
   */
  export async function probe(directory: string, available?: { uv?: string; python?: string }): Promise<Tool> {
    const existing = await Bun.file(interpreter(directory))
      .exists()
      .catch(() => false)
    if (existing) return { kind: "existing", binary: interpreter(directory) }

    const uv = available ? available.uv : (Bun.which("uv") ?? undefined)
    if (uv) return { kind: "uv", binary: uv }

    const python = available ? available.python : (Bun.which("python3") ?? Bun.which("python") ?? undefined)
    if (python) return { kind: "venv", binary: python }

    throw new Error(
      [
        "No way to create a Python environment on this machine.",
        "Install one of:",
        "  - the venv module: `apt install python3-venv` on Debian/Ubuntu (most other distributions ship it with python3)",
        "  - uv: https://docs.astral.sh/uv/getting-started/installation/",
        "OpenScience never downloads either automatically.",
      ].join("\n"),
    )
  }

  /**
   * Create the environment. A no-op when it already exists — rebuilding would
   * silently discard everything installed into it.
   *
   * `--seed` on the uv branch is load-bearing, not a nicety. `python3 -m venv`
   * bootstraps pip from `ensurepip`; `uv venv` deliberately does not, and
   * `install()` shells out to `python -m pip` regardless of who created the
   * environment. Without it the uv branch produces an environment the
   * installer cannot use at all — measured as `No module named pip` from a
   * venv that looked perfectly healthy from outside the sandbox.
   *
   * Seeding rather than adding a second `uv pip install` path keeps one
   * install code path to test and maintain, and leaves the environment usable
   * by hand. The cost is a few hundred milliseconds at creation only.
   */
  export async function create(directory: string, tool: Tool) {
    if (tool.kind === "existing") return
    await fs.mkdir(path.dirname(directory), { recursive: true })
    const argv =
      tool.kind === "uv" ? [tool.binary, "venv", "--seed", directory] : [tool.binary, "-m", "venv", directory]
    const proc = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe" })
    const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
    await proc.exited
    if (proc.exitCode !== 0) throw new Error(`Could not create the environment at ${directory}.\n${err || out}`)
  }

  /** Sandboxed argv for a command run against the environment: the same policy
   *  the kernel gets, plus write access to the environment directory. */
  async function confined(directory: string, argv: string[]) {
    const policy = await Config.trustedSandbox()
    const egress = await EgressRuntime.egressFor(policy)
    return Sandbox.wrapArgv({
      file: argv[0]!,
      args: argv.slice(1),
      workspace: [directory],
      options: { ...policy, egress },
    })
  }

  export async function install(input: {
    directory: string
    packages: string[]
    index: string
    source: boolean
    signal?: AbortSignal
  }) {
    // Inside the environment directory, so it is covered by the one writable
    // bind. Without a writable cache pip disables caching entirely and every
    // retry re-downloads every wheel.
    const cache = path.join(input.directory, ".cache")
    await fs.mkdir(cache, { recursive: true })
    // Wheels-only is a speed and reliability default, NOT a security boundary:
    // if bwrap contains agent Python at import time it contains setup.py at
    // install time.
    const policy = input.source ? [] : ["--only-binary", ":all:"]
    const argv = [
      interpreter(input.directory),
      "-m",
      "pip",
      "install",
      "--disable-pip-version-check",
      ...policy,
      ...(input.index ? ["--index-url", input.index] : []),
      ...input.packages,
    ]
    const spec = await confined(input.directory, argv)
    const proc = Bun.spawn([spec.file, ...(spec.args ?? [])], {
      env: { ...process.env, ...spec.env, PIP_CACHE_DIR: cache, TMPDIR: cache },
      stdout: "pipe",
      stderr: "pipe",
      signal: input.signal,
    })
    const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
    await proc.exited
    return { ok: proc.exitCode === 0, log: [out, err].filter(Boolean).join("\n") }
  }

  /** name → version for everything resolved into the environment, names PEP 503
   *  normalised so they compare against parsed requirements. */
  export async function freeze(directory: string) {
    const proc = Bun.spawn([interpreter(directory), "-m", "pip", "list", "--format=json"], {
      stdout: "pipe",
      stderr: "pipe",
    })
    const text = await new Response(proc.stdout).text()
    await proc.exited
    const parsed = (() => {
      try {
        return JSON.parse(text) as { name: string; version: string }[]
      } catch {
        return []
      }
    })()
    return Object.fromEntries(parsed.map((p) => [normalise(p.name), p.version]))
  }

  /**
   * Report the landed version of each requested name.
   *
   * Catches an installer that exits 0 without producing anything usable — "pip
   * said ok" and "it is actually in the environment" are different claims, and
   * only the second is worth reporting to a user.
   */
  export async function verify(directory: string, packages: string[]) {
    const frozen = await freeze(directory)
    const out: Record<string, string> = {}
    for (const name of packages) {
      const version = frozen[normalise(name)]
      if (version) out[name] = version
    }
    return out
  }

  /**
   * Turn a pip log into something a reader can act on.
   *
   * Two surfaces matter. The wheels-only rejection reads as "no such package"
   * and means "no wheel under this policy". A build failure's summary line
   * names the package, but the `fatal error:` line above it names the missing
   * system header — which usually means the install is unachievable in a
   * sandbox and a pure-Python alternative is the real answer.
   *
   * An unrecognised log passes through untouched. Inventing a diagnosis for a
   * failure mode nobody anticipated is worse than showing the log.
   */
  export function explain(log: string) {
    const wheels = log.match(/Could not find a version that satisfies the requirement (\S+)[^\n]*from versions: none/)
    if (wheels) {
      return [
        `No wheel is published for ${wheels[1]} under the current wheels-only policy.`,
        `This is not "no such package" — it may exist only as a source distribution.`,
        `Retry with source builds enabled if a compiler and headers are available.`,
      ].join(" ")
    }
    const fatal = log.match(/^\s*fatal error:\s*(.+)$/m)
    const failed = log.match(/Failed building wheel for (\S+)/)
    if (fatal) {
      return [
        failed ? `Building ${failed[1]} failed.` : "A wheel build failed.",
        `The cause is a missing system dependency: ${fatal[1]!.trim()}`,
        `A sandboxed install cannot add system packages — prefer a pure-Python alternative, or a package that publishes wheels.`,
      ].join(" ")
    }
    return log.trim()
  }
}
