import { expect, test } from "bun:test"
import { Environment } from "../../src/package/environment"
import { KernelProcessIdentity } from "../../src/science/kernel/process"

const seed = async (project: string, name: string) =>
  Environment.write(project, {
    name,
    language: "python",
    requested: [],
    installed: {},
    total: 0,
    createdAt: 1,
    updatedAt: 1,
  })

test("a claim by a live process reconciles as still running", async () => {
  const project = "proj_reconcile_live"
  await seed(project, "live")
  // This process is by definition alive, so it stands in for a live installer.
  await Environment.claim(project, "live", process.pid, KernelProcessIdentity.startToken(process.pid))
  const outcomes = await Environment.reconcile(project)
  expect(outcomes.find((o) => o.name === "live")?.outcome).toBe("running")
})

test("a live pid with no token available still reconciles as running", async () => {
  // Windows has neither the /proc nor the `ps -o lstart=` branch, so the token
  // is undefined there for every process. Treating that as unproven would mark
  // every Windows install unknown forever and every environment permanently
  // suspect. `matches()` already takes liveness alone as sufficient in that
  // case; reconcile follows the same rule.
  const project = "proj_reconcile_untokened"
  await seed(project, "untokened")
  await Environment.claim(project, "untokened", process.pid, undefined)
  const outcomes = await Environment.reconcile(project)
  expect(outcomes.find((o) => o.name === "untokened")?.outcome).toBe("running")
})

test("a claim by a dead pid reconciles as unknown, not as success", async () => {
  const project = "proj_reconcile_dead"
  await seed(project, "dead")
  const proc = Bun.spawn(["/bin/true"], { stdout: "ignore", stderr: "ignore" })
  const pid = proc.pid
  const captured = KernelProcessIdentity.startToken(pid)
  await proc.exited
  // `await proc.exited` is not the same as "the pid is gone": a just-reaped
  // child can stay signalable briefly, and on a macOS runner it did — the
  // claim then reconciled as "running" and this failed for a reason that had
  // nothing to do with reconcile. Wait for the premise to actually hold, and
  // fail loudly if it never does rather than asserting on a live pid.
  for (let i = 0; i < 100; i++) {
    try {
      process.kill(pid, 0)
    } catch {
      break
    }
    await Bun.sleep(20)
  }
  expect(() => process.kill(pid, 0)).toThrow()
  await Environment.claim(project, "dead", pid, captured)
  const outcomes = await Environment.reconcile(project)
  // Not "fine": pip has no transactions, so an interrupted install may have
  // written a partial tree. Silently trusting it is how a half-installed
  // environment becomes a mystery ImportError three turns later.
  expect(outcomes.find((o) => o.name === "dead")?.outcome).toBe("unknown")
})

test("a claim whose token no longer matches reconciles as unknown", async () => {
  // pid reuse: the number is alive but it is a different process.
  const project = "proj_reconcile_reused"
  await seed(project, "reused")
  await Environment.claim(project, "reused", process.pid, "not-the-real-token")
  const outcomes = await Environment.reconcile(project)
  expect(outcomes.find((o) => o.name === "reused")?.outcome).toBe("unknown")
})

test("a corrupt claim file reconciles as unknown rather than throwing", async () => {
  const project = "proj_reconcile_corrupt"
  await seed(project, "corrupt")
  await Environment.claim(project, "corrupt", process.pid, undefined)
  await Bun.write(Environment.claimPath(project, "corrupt"), "{not json")
  const outcomes = await Environment.reconcile(project)
  expect(outcomes.find((o) => o.name === "corrupt")?.outcome).toBe("unknown")
})

test("reconcile clears a resolved claim so it is not reported twice", async () => {
  const project = "proj_reconcile_once"
  await seed(project, "once")
  await Environment.claim(project, "once", 999_999, "gone")
  expect(await Environment.reconcile(project)).toHaveLength(1)
  expect(await Environment.reconcile(project)).toHaveLength(0)
})

test("reconcile keeps a claim that is still running, so a later check still sees it", async () => {
  const project = "proj_reconcile_keep"
  await seed(project, "keep")
  await Environment.claim(project, "keep", process.pid, KernelProcessIdentity.startToken(process.pid))
  expect(await Environment.reconcile(project)).toHaveLength(1)
  expect(await Environment.reconcile(project)).toHaveLength(1)
})

test("a project with no claims reconciles to nothing", async () => {
  expect(await Environment.reconcile("proj_no_claims_at_all")).toEqual([])
})

const python = Bun.which("python3")
const live = (await import("../../src/sandbox/sandbox")).Sandbox.backend() !== "none" && Boolean(python)

test.skipIf(!live)(
  "wait:false returns before the install finishes, then the package really lands",
  async () => {
    const { Instance } = await import("../../src/project/instance")
    const { PackageTool } = await import("../../src/tool/package")
    const { Installer } = await import("../../src/package/installer")
    const { executionSession, tmpdir } = await import("../fixture/fixture")
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const session = await executionSession()
        const ctx = {
          sessionID: session.id,
          messageID: "",
          callID: "",
          agent: "research",
          abort: AbortSignal.any([]),
          messages: [],
          metadata: () => {},
          ask: async () => {},
        }
        const tool = await PackageTool.init()
        const result = await tool.execute(
          { packages: ["tqdm"], environment: "async", language: "python" as const, source: false, wait: false },
          ctx as never,
        )

        // No versions, and it does not claim success — there is nothing to
        // report yet, and inventing a version is what the contract forbids.
        expect(result.metadata.installed).toBe(false)
        expect(result.metadata.versions).toEqual({})
        expect(result.output).toContain("still running")

        // The work really is in flight: taking the lock waits it out, and the
        // package is present afterwards.
        const directory = Environment.directory(Instance.project.id, "async")
        await Environment.lock(Instance.project.id, "async", async () => {})
        expect((await Installer.verify(directory, ["tqdm"]))["tqdm"]).toMatch(/^\d/)

        // And the claim is cleared once it finishes, so a later reconcile does
        // not report a phantom install.
        expect(await Environment.reconcile(Instance.project.id)).toEqual([])
      },
    })
  },
  600_000,
)
