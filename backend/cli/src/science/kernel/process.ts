import fs from "node:fs"
import type { ChildProcess } from "node:child_process"
import type { KernelProcess } from "./types"

const hooks = new Set<() => void>()
let hooked = false

/**
 * The platform start token for a pid: field 19 of `/proc/<pid>/stat` on Linux,
 * `ps -o lstart=` on darwin.
 *
 * **Undefined on Windows**, which has neither branch, and undefined whenever
 * the read fails. Callers must treat "no token" as "cannot distinguish pid
 * reuse", never as "not running" — see `matches` and `running`, which both
 * fall back to bare liveness in that case.
 */
function token(pid: number) {
  if (process.platform === "linux") {
    try {
      const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8")
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ")
      const start = fields[19]
      return start ? `linux:${start}` : undefined
    } catch {
      return
    }
  }
  if (process.platform !== "darwin") return
  const result = Bun.spawnSync(["ps", "-o", "lstart=", "-p", String(pid)], {
    stdout: "pipe",
    stderr: "ignore",
  })
  const start = result.success ? result.stdout.toString().trim() : ""
  return start ? `darwin:${start}` : undefined
}

export namespace KernelProcessIdentity {
  export function onExit(fn: () => void) {
    hooks.add(fn)
    if (hooked) return
    hooked = true
    process.on("exit", () => {
      for (const hook of hooks) hook()
    })
    process.on("SIGTERM", () => process.exit(128 + 15))
    process.on("SIGINT", () => process.exit(128 + 2))
  }

  export function capture(proc: ChildProcess): KernelProcess | undefined {
    if (!proc.pid) return
    return {
      pid: proc.pid,
      startedAt: Date.now(),
      token: token(proc.pid),
    }
  }

  /** The start token for a pid, or undefined where the platform cannot supply
   *  one. Exported so callers holding a persisted pid — an installer claim, say
   *  — can capture the same value `capture()` stores for a kernel. */
  export function startToken(pid: number) {
    return token(pid)
  }

  /**
   * Liveness for a bare pid + token pair, the shape a persisted record has
   * after a restart when no `ChildProcess` survives.
   *
   * Applies the same fallback rule as `matches`: when no token was captured —
   * Windows, or a read that failed — liveness alone is sufficient. Demanding a
   * token match there would report every Windows process as dead, which for
   * the installer claim would mark every environment permanently suspect.
   */
  export function running(pid: number, value?: string) {
    try {
      process.kill(pid, 0)
    } catch {
      return false
    }
    if (!value) return true
    return token(pid) === value
  }

  export function matches(proc: ChildProcess, identity?: KernelProcess) {
    if (!identity || proc.pid !== identity.pid || proc.exitCode !== null) return false
    try {
      process.kill(identity.pid, 0)
    } catch {
      return false
    }
    if (!identity.token) return true
    return token(identity.pid) === identity.token
  }
}
