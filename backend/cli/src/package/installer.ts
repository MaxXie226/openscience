import fs from "fs/promises"
import path from "path"
import { Config } from "../config/config"
import { Global } from "../global"
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
    // `--system-site-packages` is not a convenience, it repairs a cliff.
    //
    // A kernel binds to the managed environment as soon as one exists, and
    // falls back to the host interpreter while it does not. So without this,
    // the FIRST install of anything silently removed every host package from
    // every kernel in the project: install `tqdm`, lose `numpy`. Measured in
    // real use — the notebook tool advertises numpy/pandas/scipy/matplotlib as
    // pre-imported, and they vanished the moment an environment appeared.
    //
    // Inheriting is strictly a superset of the behaviour kernels had before
    // managed environments existed, when they simply WERE the host
    // interpreter, so it exposes nothing new: host site-packages was already
    // readable under `--ro-bind / /`. The environment's own packages still take
    // precedence, so installing a newer version shadows the host's.
    //
    // The cost is that the environment is not hermetic. A hermetic mode is a
    // reasonable future flag; it is the wrong default for a tool whose users
    // expect the scientific stack to be there.
    const argv =
      tool.kind === "uv"
        ? [tool.binary, "venv", "--seed", "--system-site-packages", directory]
        : [tool.binary, "-m", "venv", "--system-site-packages", directory]
    const proc = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe" })
    const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
    await proc.exited
    if (proc.exitCode !== 0) throw new Error(`Could not create the environment at ${directory}.\n${err || out}`)
  }

  /**
   * The wheel cache, shared by every environment on the machine.
   *
   * Deliberately NOT inside the environment directory, which is where it lived
   * first. A per-environment cache means every new environment re-downloads
   * everything: measured at 34 MB and a full download for scipy alone, in a
   * second environment that had just been populated in the first — and the
   * packages that make this hurt are the large ones, where it is hundreds of
   * megabytes per environment.
   *
   * It is our own cache directory rather than user data, so sharing it across
   * projects costs nothing in isolation terms. pip's cache is content-addressed
   * and safe for concurrent readers and writers, which matters because the
   * per-environment lock does not serialise installs into DIFFERENT
   * environments.
   */
  const shared = () => path.join(Global.Path.cache, "pip")

  /** Sandboxed argv for a command run against the environment: the same policy
   *  the kernel gets, plus write access to the environment directory and the
   *  shared wheel cache. */
  async function confined(directory: string, argv: string[]) {
    const policy = await Config.trustedSandbox()
    const egress = await EgressRuntime.egressFor(policy)
    return Sandbox.wrapArgv({
      file: argv[0]!,
      args: argv.slice(1),
      workspace: [directory, shared()],
      options: { ...policy, egress },
    })
  }

  /**
   * The most recent line of pip output worth showing a human.
   *
   * pip reports phase and size continuously — "Collecting torch", "Downloading
   * torch-…whl (906.4 MB)", "Installing collected packages: …" — and all of it
   * used to be buffered and discarded unless the install failed. A pytorch
   * install sat behind an unchanging ellipsis for 1m37s while that ran.
   *
   * Progress-bar redraws and continuation lines are skipped: they are noise at
   * one line of visible status, and a bar rendered to a pipe is mostly control
   * characters anyway.
   */
  const progressLine = (chunk: string) => {
    const lines = chunk
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !/^[━╸\-=|/\\ ]*$/.test(l) && !l.startsWith("|"))
    return lines.at(-1)
  }

  export async function install(input: {
    directory: string
    packages: string[]
    index: string
    source: boolean
    signal?: AbortSignal
    /** Called with a short status as pip reports it. */
    onProgress?: (status: string) => void
  }) {
    // Two different directories with two different lifetimes. The wheel cache is
    // shared across environments so a package is downloaded once per machine;
    // the scratch directory pip unpacks into stays environment-local, because it
    // is throwaway and sharing it would let concurrent installs collide.
    const cache = shared()
    const scratch = path.join(input.directory, ".tmp")
    await fs.mkdir(cache, { recursive: true })
    await fs.mkdir(scratch, { recursive: true })
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
      env: { ...process.env, ...spec.env, PIP_CACHE_DIR: cache, TMPDIR: scratch },
      stdout: "pipe",
      stderr: "pipe",
      signal: input.signal,
    })
    // Drained as it arrives rather than awaited whole, so a caller can report
    // progress. The full text is still accumulated: `explain()` needs the
    // entire log to find the `fatal error:` line, which is rarely last.
    const drain = async (stream: ReadableStream<Uint8Array>, report: boolean) => {
      const reader = stream.getReader()
      const decoder = new TextDecoder()
      let text = ""
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        const piece = decoder.decode(value, { stream: true })
        text += piece
        if (!report || !input.onProgress) continue
        const status = progressLine(piece)
        if (status) input.onProgress(status)
      }
      return text
    }
    // pip writes its progress to stdout and its diagnostics to stderr; only the
    // former is worth surfacing as status.
    const [out, err] = await Promise.all([drain(proc.stdout, true), drain(proc.stderr, false)])
    await proc.exited
    return { ok: proc.exitCode === 0, log: [out, err].filter(Boolean).join("\n") }
  }

  /** name → version for everything resolved into the environment, names PEP 503
   *  normalised so they compare against parsed requirements. */
  export async function freeze(directory: string) {
    // `--local` matters now that environments inherit system site-packages:
    // without it this reports every host package too, which would make `total`
    // meaningless, bury the requested names in the agent's inventory, and turn
    // `additive()` into a comparison against the machine rather than against
    // the environment. What this environment OWNS is the question being asked.
    const proc = Bun.spawn([interpreter(directory), "-m", "pip", "list", "--local", "--format=json"], {
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
   * Report the version of each requested name **as the environment's own
   * interpreter resolves it**, whether it lives in the environment or is
   * inherited from the host.
   *
   * Asked of the interpreter rather than of `freeze()`, which lists only what
   * the environment owns. Since environments inherit system site-packages, pip
   * treats a host-provided package as already satisfied and installs nothing —
   * so a `freeze`-based answer reported "(nothing reported)" for a request that
   * is, from the user's seat, perfectly satisfied. The question worth answering
   * is "can the kernel use it, and at what version", and only the interpreter
   * can answer that.
   *
   * `importlib.metadata` rather than a real import: it reads distribution
   * metadata, so it needs no heavy import, triggers no import side effects, and
   * handles name normalisation itself. It still catches an installer that
   * exited 0 without producing anything usable, which is the point.
   */
  export async function verify(directory: string, packages: string[]) {
    const script = [
      "import json, sys",
      "from importlib.metadata import version, PackageNotFoundError",
      "out = {}",
      "for name in json.loads(sys.argv[1]):",
      "    try:",
      "        out[name] = version(name)",
      "    except PackageNotFoundError:",
      "        pass",
      "print(json.dumps(out))",
    ].join("\n")
    const proc = Bun.spawn([interpreter(directory), "-c", script, JSON.stringify(packages)], {
      stdout: "pipe",
      stderr: "pipe",
    })
    const text = await new Response(proc.stdout).text()
    await proc.exited
    try {
      return JSON.parse(text) as Record<string, string>
    } catch {
      return {}
    }
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
