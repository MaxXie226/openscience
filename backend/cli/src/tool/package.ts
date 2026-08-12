import z from "zod"
import { Environment } from "../package/environment"
import { Installer } from "../package/installer"
import { Requirement } from "../package/requirement"
import { Instance } from "../project/instance"
import { KernelRuntime } from "../science/kernel/registry"
import { Tool } from "./tool"

/** The public index, shown on the card and matched by the permission system.
 *  Redacted through `Requirement.redact` so a credentialled mirror never puts
 *  a secret on the card and never fragments a standing grant. */
const DEFAULT_INDEX = Requirement.redact("https://pypi.org/simple")

export const PackageTool = Tool.define("package_install", {
  description: [
    "Install packages into a managed, named environment that kernels can use.",
    "This is the only way to add packages. Shell installers (pip, uv pip, conda, poetry) are refused.",
    "An environment is scoped to one language: Python packages go to a python environment, R packages to an R environment.",
    "A fully-satisfied request installs nothing — check the environment inventory in your context before calling.",
    "Installing restarts kernels bound to that environment only when the change is not purely additive.",
  ].join("\n"),
  parameters: z.object({
    packages: z
      .array(z.string().trim().min(1))
      .min(1)
      .describe("Package requirements to install, e.g. ['numpy', 'pandas>=2.2']"),
    environment: z
      .string()
      .trim()
      .min(1)
      .max(64)
      .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/)
      .default("default")
      .describe("Target environment. Created on first install."),
    language: z
      .enum(["python", "r"])
      .default("python")
      .describe("Environment language. An environment is scoped to one."),
    source: z
      .boolean()
      .default(false)
      .describe("Allow source builds. Default is wheels-only, which is faster and more reliable."),
  }),
  async execute(params, ctx) {
    const project = Instance.project.id
    const name = params.environment
    const directory = Environment.directory(project, name)
    const before = await Environment.read(project, name)

    // Parsed for its names only. Resolution happens after approval — the card
    // shows the request, so approving two names must not silently approve the
    // closure they pull in.
    const parsed = params.packages.map((p) => Requirement.parse(p))

    // Already satisfied: skip outright — no card, no install, no restart.
    // Nothing privileged happens, so nothing needs approving, and a
    // fully-satisfied request is not worth a turn.
    const satisfied = before && parsed.every((p) => before.installed[p.name])
    if (satisfied) {
      // The same metadata shape as the install branch below, deliberately.
      // Two shapes would make every consumer — the UI, the session record, a
      // test — handle a union whose arms differ only in which keys exist.
      const versions = Object.fromEntries(parsed.map((p) => [p.name, before.installed[p.name]!]))
      const listed = Object.entries(versions)
        .map(([k, v]) => `${k} ${v}`)
        .join(", ")
      return {
        title: `Already installed · ${name}`,
        output: `Nothing to do. ${listed} already present in ${name}.`,
        metadata: {
          environment: name,
          installed: false,
          ok: true,
          additive: true,
          versions,
          total: before.total,
        },
      }
    }

    const pattern = Requirement.pattern({
      packages: params.packages,
      environment: name,
      index: DEFAULT_INDEX,
    })

    ctx.metadata({ title: `Install · ${name}`, metadata: { environment: name, packages: params.packages } })

    // The ordinary contract, not modal's. Installing a library must not be
    // gated more strictly than running arbitrary code, because it costs
    // nothing — hence no digest and no spendFilter entry. The command string is
    // readable, and changes whenever the approved action changes, so the prompt
    // reappears for free when it should.
    await ctx.ask({
      permission: "package_install",
      patterns: [pattern],
      always: ["install*"],
      metadata: { environment: name, packages: params.packages, index: DEFAULT_INDEX },
    })

    return await Environment.lock(project, name, async () => {
      const tool = await Installer.probe(directory)
      await Installer.create(directory, tool)

      const snapshot = await Installer.freeze(directory)
      const result = await Installer.install({
        directory,
        packages: params.packages,
        index: "",
        source: params.source,
        signal: ctx.abort,
      })

      // Modern pip builds every wheel before the install phase, so a build
      // failure aborts before anything is committed — verified during design,
      // where a failing package's cleanly-resolving dependency was downloaded
      // and still not installed. There is no subset to keep and nothing to
      // retry, so this reports the cause and stops.
      if (!result.ok) throw new Error(Installer.explain(result.log))

      const after = await Installer.freeze(directory)
      const versions = await Installer.verify(
        directory,
        parsed.map((p) => p.name),
      )

      const requested = Array.from(new Set([...(before?.requested ?? []), ...parsed.map((p) => p.name)]))
      await Environment.write(project, {
        name,
        // Defaulted here rather than relied on from the schema: `execute` is
        // reachable without zod having applied parameter defaults, and an
        // undefined language used to produce a manifest that could never be
        // read back.
        language: params.language ?? "python",
        requested,
        installed: after,
        total: Object.keys(after).length,
        createdAt: before?.createdAt ?? Date.now(),
        updatedAt: Date.now(),
      })

      const additive = Environment.additive(snapshot, after)
      if (!additive) await KernelRuntime.restartEnvironment(project, name)

      const landed = Object.entries(versions)
        .map(([k, v]) => `${k} ${v}`)
        .join(", ")
      return {
        title: `Installed · ${name}`,
        output: [
          `Installed into ${name}: ${landed || "(nothing reported)"}.`,
          `${Object.keys(after).length} packages total in the environment.`,
          additive
            ? "Purely additive — running kernels kept their state."
            : "Not purely additive — kernels bound to this environment restarted and their variables were discarded.",
        ].join("\n"),
        metadata: {
          environment: name,
          installed: true,
          ok: true,
          additive,
          versions,
          total: Object.keys(after).length,
        },
      }
    })
  },
})
