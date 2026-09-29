import { For, Show, createMemo, createSignal } from "solid-js"
import { Button } from "@synsci/ui/button"
import { useDialog } from "@synsci/ui/context/dialog"
import { Select } from "@synsci/ui/select"
import type { Provider } from "@synsci/sdk/v2/client"
import { confirmDialog } from "@/atlas/dialogs"
import { useGlobalSDK } from "@/context/global-sdk"
import { useGlobalSync } from "@/context/global-sync"
import { useLanguage } from "@/context/language"
import { useProviders } from "@/hooks/use-providers"
import type { dict } from "@/i18n/en"
import { MODEL_PROVIDERS, MODEL_PROVIDER_LABELS, modelProvider } from "./model-providers"
import { ProviderLogo } from "./ProviderLogo"
import { Icon } from "@synsci/ui/icon"

/**
 * `note` says where a key that this panel cannot delete actually lives, so the
 * reader knows where to go and change it. Every non-removable source used to
 * render one blanket "external", which is wrong for a key the user
 * set themselves in a .env or a config file — nobody else manages it, and the
 * phrase suggests an administrator does.
 */
type ProviderSource = Provider["source"] | "managed"
type Copy = keyof typeof dict

const SOURCES: Record<ProviderSource, { label: Copy; removable: boolean; title: Copy; note?: Copy }> = {
  api: {
    label: "settings.providerKeys.source.api.label",
    removable: true,
    title: "settings.providerKeys.source.api.title",
  },
  env: {
    label: "settings.providerKeys.source.env.label",
    removable: false,
    note: "settings.providerKeys.source.env.note",
    title: "settings.providerKeys.source.env.title",
  },
  config: {
    label: "settings.providerKeys.source.config.label",
    removable: false,
    note: "settings.providerKeys.source.config.note",
    title: "settings.providerKeys.source.config.title",
  },
  custom: {
    label: "settings.providerKeys.source.custom.label",
    removable: false,
    note: "settings.providerKeys.source.config.note",
    title: "settings.providerKeys.source.custom.title",
  },
  workspace: {
    label: "settings.providerKeys.source.workspace.label",
    removable: false,
    note: "settings.providerKeys.source.workspace.note",
    title: "settings.providerKeys.source.workspace.title",
  },
  managed: {
    label: "settings.providerKeys.source.managed.label",
    removable: false,
    note: "settings.providerKeys.source.managed.note",
    title: "settings.providerKeys.source.managed.title",
  },
}

export function ProviderKeys(props: { onError?: (error: string | undefined) => void }) {
  const sdk = useGlobalSDK()
  const sync = useGlobalSync()
  const providers = useProviders()
  const dialog = useDialog()
  const language = useLanguage()
  const [provider, setProvider] = createSignal<string>(MODEL_PROVIDERS[0].id)
  const [key, setKey] = createSignal("")
  const [adding, setAdding] = createSignal(false)
  const [saving, setSaving] = createSignal(false)
  const reason = (error: unknown) => (error instanceof Error ? error.message : String(error))
  const connected = createMemo(() =>
    providers
      .connected()
      .filter((item) => item.source !== "managed" && MODEL_PROVIDERS.some((provider) => provider.id === item.id)),
  )
  const source = (item: { id: string; source?: ProviderSource }) => SOURCES[item.source ?? "api"]
  const refreshAfterSave = (
    failed: "settings.providerKeys.saved.reloadFailed" | "settings.providerKeys.removed.reloadFailed",
  ) => {
    void sync.refreshProviders().catch((error) => props.onError?.(language.t(failed, { reason: reason(error) })))
  }
  const save = async () => {
    const value = key().trim()
    if (!value || saving()) return
    // An Ace key is a Wallet credential, not a provider key: say where it goes
    // instead of letting the server's refusal explain it.
    if (/^(?:osk_|thk_|thk-)/.test(value)) {
      props.onError?.(language.t("settings.providerKeys.aceKey"))
      return
    }
    setSaving(true)
    props.onError?.(undefined)
    try {
      await sdk.client.auth.set({ providerID: provider(), auth: { type: "api", key: value } })
      setKey("")
      setAdding(false)
      // The credential is on disk now. Re-enable the form before rebuilding
      // the large provider catalog; auth.set already invalidates the server's
      // provider map, so disposing every workspace here only added latency.
      setSaving(false)
      refreshAfterSave("settings.providerKeys.saved.reloadFailed")
    } catch (error) {
      props.onError?.(reason(error))
    } finally {
      setSaving(false)
    }
  }

  const remove = async (providerID: string) => {
    if (saving()) return
    const label = MODEL_PROVIDER_LABELS[providerID] ?? providerID
    const confirmed = await confirmDialog(dialog, {
      title: language.t("settings.providerKeys.remove.title", { provider: label }),
      message: language.t("settings.providerKeys.remove.message"),
      confirmLabel: language.t("settings.providerKeys.remove.confirm"),
      danger: true,
    })
    if (!confirmed) return
    setSaving(true)
    props.onError?.(undefined)
    try {
      await sdk.client.auth.remove({ providerID })
      setSaving(false)
      refreshAfterSave("settings.providerKeys.removed.reloadFailed")
    } catch (error) {
      props.onError?.(reason(error))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div class="models-provider-keys">
      <div class="settings-row models-compact-row models-provider-key-heading">
        <div class="models-provider-identity">
          <span class="settings-row-logo" aria-hidden="true">
            <Icon name="providers" size="small" />
          </span>
          <div class="models-provider-copy">
            <span class="text-14-medium text-text-strong">{language.t("settings.providerKeys.title")}</span>
            <span class="text-12-regular text-text-weak">{language.t("settings.providerKeys.description")}</span>
          </div>
        </div>
        <span class="models-row-action">
          <Button
            class="settings-panel-action models-secondary-action"
            type="button"
            size="small"
            variant="secondary"
            aria-expanded={adding()}
            aria-controls="models-add-provider-key"
            disabled={saving()}
            onClick={() => {
              if (adding()) setKey("")
              setAdding((open) => !open)
            }}
          >
            {adding() ? language.t("common.cancel") : language.t("settings.providerKeys.add")}
          </Button>
        </span>
      </div>

      <Show when={adding()}>
        <form
          id="models-add-provider-key"
          class="settings-provider-key-form models-provider-key-form"
          onSubmit={(event) => {
            event.preventDefault()
            void save()
          }}
        >
          <label class="models-key-field">
            <span class="text-12-medium text-text-weak">{language.t("settings.providerKeys.field.provider")}</span>
            <div class="models-provider-select">
              <Select
                aria-label={language.t("settings.providerKeys.field.provider.ariaLabel")}
                class="models-provider-options"
                options={[...MODEL_PROVIDERS]}
                current={modelProvider(provider())}
                value={(item) => item.id}
                label={(item) => item.label}
                disabled={saving()}
                onSelect={(item) => item && setProvider(item.id)}
                variant="secondary"
                size="small"
                triggerVariant="settings"
                triggerStyle={{
                  width: "100%",
                  "justify-content": "space-between",
                }}
              />
            </div>
          </label>
          <label class="models-key-field">
            <span class="text-12-medium text-text-weak">{language.t("provider.connect.method.apiKey")}</span>
            <input
              type="password"
              autocomplete="off"
              spellcheck={false}
              disabled={saving()}
              value={key()}
              onInput={(event) => setKey(event.currentTarget.value)}
              placeholder={modelProvider(provider()).placeholder}
              class="settings-field settings-provider-key models-key-input"
            />
          </label>
          <Button
            class="settings-panel-action models-primary-action models-save-key"
            type="submit"
            size="small"
            variant="primary"
            disabled={saving() || !key().trim()}
          >
            {saving() ? language.t("settings.saving") : language.t("settings.providerKeys.save")}
          </Button>
        </form>
      </Show>

      <Show when={connected().length > 0}>
        <div class="models-connected-providers">
          <For each={connected()}>
            {(item) => (
              <div class="settings-row models-compact-row models-provider-row">
                <div class="models-provider-identity min-w-0 flex-1 basis-[220px]">
                  <span class="settings-row-logo" aria-hidden="true">
                    <ProviderLogo id={item.id} label={MODEL_PROVIDER_LABELS[item.id] ?? item.id} size="small" />
                  </span>
                  <div class="models-provider-copy">
                    <span class="truncate text-14-medium text-text-strong">
                      {MODEL_PROVIDER_LABELS[item.id] ?? item.id}
                    </span>
                    <div class="models-provider-meta">
                      <span class="models-provider-source" title={language.t(source(item).title)}>
                        {language.t(source(item).label)}
                      </span>
                    </div>
                  </div>
                </div>
                <span class="settings-row-status">{language.t("settings.providerKeys.status.available")}</span>
                <Show
                  when={source(item).removable}
                  fallback={
                    <span
                      class="models-provider-note text-12-regular text-text-weak"
                      title={language.t(source(item).title)}
                    >
                      {language.t(source(item).note ?? "settings.providerKeys.source.external")}
                    </span>
                  }
                >
                  <span class="models-row-action">
                    <Button
                      class="settings-panel-action settings-panel-action--quiet models-secondary-action"
                      size="small"
                      variant="secondary"
                      disabled={saving()}
                      onClick={() => void remove(item.id)}
                    >
                      {language.t("settings.providerKeys.remove")}
                    </Button>
                  </span>
                </Show>
              </div>
            )}
          </For>
        </div>
      </Show>
      <Show when={connected().length === 0 && !adding()}>
        <p class="models-provider-empty" role="status">
          {language.t("settings.providerKeys.empty")}
        </p>
      </Show>
    </div>
  )
}
