import fs from "fs/promises"
import path from "path"
import z from "zod"
import { Global } from "../global"

/**
 * Environment state. No process spawning lives here — the installer owns that.
 *
 * The manifest is the source of truth and the directory is derived, therefore a
 * cache. That is why they sit in different roots: `Global.Path.cache` may be
 * cleared by the user or a cleaner at any time, and an environment must be
 * rebuildable from its manifest afterwards. Putting the manifest inside the
 * directory would make a cache clean an unrecoverable data loss.
 */
export namespace Environment {
  export const Language = z.enum(["python", "r"])
  export type Language = z.infer<typeof Language>

  export const Record = z.object({
    name: z.string(),
    language: Language,
    /** Only what was explicitly asked for, never the resolved closure. */
    requested: z.array(z.string()).default([]),
    /** Resolved name → version, as the installer reported it after the fact. */
    installed: z.record(z.string(), z.string()).default({}),
    /** Size of the resolved closure, reported as a number rather than listed. */
    total: z.number().int().nonnegative().default(0),
    createdAt: z.number(),
    updatedAt: z.number(),
  })
  export type Record = z.infer<typeof Record>

  export function manifest(projectID: string, name: string) {
    return path.join(Global.Path.data, "envs", projectID, `${name}.json`)
  }

  export function directory(projectID: string, name: string) {
    return path.join(Global.Path.cache, "envs", projectID, name)
  }

  export async function read(projectID: string, name: string) {
    const file = Bun.file(manifest(projectID, name))
    if (!(await file.exists())) return undefined
    const parsed = Record.safeParse(await file.json().catch(() => undefined))
    return parsed.success ? parsed.data : undefined
  }

  export async function write(projectID: string, value: Record) {
    const file = manifest(projectID, value.name)
    await fs.mkdir(path.dirname(file), { recursive: true })
    await Bun.write(file, JSON.stringify(value, null, 2))
  }

  /** Every environment for a project. A manifest that fails to parse is skipped
   *  rather than thrown on: one hand-edited or half-written file must not make
   *  every other environment in the project invisible. */
  export async function list(projectID: string) {
    const dir = path.join(Global.Path.data, "envs", projectID)
    const names = await fs.readdir(dir).catch(() => [] as string[])
    const values = await Promise.all(
      names.filter((n) => n.endsWith(".json")).map((n) => read(projectID, n.slice(0, -".json".length))),
    )
    return values.filter((v): v is Record => Boolean(v))
  }

  /**
   * Purely additive means every package present before is present after at the
   * same version.
   *
   * Additive changes leave a live kernel correct: a new module imports on first
   * use. Any removal, downgrade or version change does not — a module already
   * loaded into the interpreter stays at the old version in memory while the
   * files on disk say otherwise, which is worse than an obvious failure because
   * it is silent. That asymmetry is the whole reason this function exists
   * rather than restarting on every install.
   */
  export function additive(before: Record["installed"], after: Record["installed"]) {
    return Object.entries(before).every(([name, version]) => after[name] === version)
  }

  const held = new Map<string, Promise<unknown>>()

  const slot = (projectID: string, name: string) => `${projectID} ${name}`

  /** True while something holds this environment's lock. */
  export function busy(projectID: string, name: string) {
    return held.has(slot(projectID, name))
  }

  /**
   * Serialise work per environment. Other environments stay fully usable — the
   * lock is per-env precisely so one long install does not stop every kernel in
   * the project.
   *
   * The chain is built from the previous entry rather than awaited in place, so
   * a caller arriving mid-install queues instead of racing. `previous.then(fn,
   * fn)` runs the next body whether the one before it resolved or rejected: a
   * failed install must not cancel the work queued behind it. The slot is
   * cleared only if it is still ours, so a later waiter that replaced it is not
   * evicted — and it is cleared in a `finally`, because a lock that survives a
   * throw would brick the environment for the process lifetime, which is the
   * latching bug the egress runtime shipped with.
   */
  export async function lock<T>(projectID: string, name: string, fn: () => Promise<T>): Promise<T> {
    const id = slot(projectID, name)
    const previous = held.get(id) ?? Promise.resolve()
    const run = previous.then(fn, fn)
    const tracked = run.catch(() => undefined)
    held.set(id, tracked)
    try {
      return await run
    } finally {
      if (held.get(id) === tracked) held.delete(id)
    }
  }
}
