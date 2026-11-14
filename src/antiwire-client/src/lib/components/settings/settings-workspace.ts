import { api, type SettingsDto } from '#lib/api/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import { resetPowerUserOptions } from '#lib/models/settings-mapper.ts';
import {
  applyDnsProtocol,
  customResolverInvalid,
  dnsProtocol,
  dnsProviderOptionList,
  safeDnsProvider,
  settingsFieldsValid,
  showSave,
  siemHostInvalid,
  siemPortInvalid,
  siemProtocolOptions,
  siemProtocolValue,
  siemUrlInvalid,
  type SettingsSection,
} from './form/settings-form';
import { TrackedReactive } from '#lib/state/tracked.ts';

export type SettingsApiClient = Pick<typeof api, 'getSettings' | 'updateSettings'>;

type SecretKey = 'aiApiKey' | 'siemAuthToken';
type SecretClearKey = 'clearAiApiKey' | 'clearSiemAuthToken';

export type SettingsHost = {
  readonly connected: boolean;
  toast(title: string, body: string, color: string): void;
  /** After the daemon accepted a save; `before` is what was saved until now. */
  saved?(before: SettingsDto | null, after: SettingsDto): void;
};

/**
 * Settings route state and daemon writes. The page owns the connect
 * effect; this class owns load/save, DNS protocol switching, and the
 * power-user dialog so those stay testable without a DOM.
 */
export class SettingsWorkspace extends TrackedReactive {
  section: SettingsSection = 'General';
  settings: SettingsDto | null = null;
  loading = false;
  loadFailed = false;
  saving = false;
  editRevision = 0;
  savedRevision = 0;
  powerUserDialogOpen = false;
  private loadGeneration = 0;
  private savedSettings: SettingsDto | null = null;

  discardChanges = () => {
    if (!this.savedSettings || this.saving || this.loading) return;
    this.settings = { ...this.savedSettings };
    this.editRevision++;
    this.savedRevision = this.editRevision;
    this.powerUserDialogOpen = false;
  };

  constructor(
    private readonly client: SettingsApiClient,
    private readonly host: SettingsHost,
  ) {
    super();
    this.track(
      'section',
      'settings',
      'loading',
      'loadFailed',
      'saving',
      'editRevision',
      'savedRevision',
      'powerUserDialogOpen',
    );
  }

  /**
   * Drops any load still in flight. The page calls this when it unmounts or
   * the daemon disconnects; a later `loadSettings` starts afresh, so a
   * StrictMode remount just loads again.
   */
  dispose = () => {
    this.loadGeneration++;
    this.loading = false;
  };

  setSection = (section: SettingsSection) => {
    this.section = section;
  };

  setPowerUserDialogOpen = (open: boolean) => {
    this.powerUserDialogOpen = open;
  };

  get connected() {
    return this.host.connected;
  }

  get isDirty() {
    return this.editRevision !== this.savedRevision;
  }

  get customResolverInvalid() {
    return customResolverInvalid(this.settings);
  }

  get siemHostInvalid() {
    return siemHostInvalid(this.settings);
  }

  get siemPortInvalid() {
    return siemPortInvalid(this.settings);
  }

  get siemUrlInvalid() {
    return siemUrlInvalid(this.settings);
  }

  get settingsFieldsValid() {
    return settingsFieldsValid(this.settings);
  }

  get showSave() {
    return showSave({
      connected: this.connected,
      settings: this.settings,
      section: this.section,
      isDirty: this.isDirty,
      fieldsValid: this.settingsFieldsValid,
    });
  }

  get dnsProtocol() {
    return this.settings ? dnsProtocol(this.settings) : 'doh';
  }

  get dnsProviderOptionList() {
    return this.settings ? dnsProviderOptionList(this.settings) : [];
  }

  get safeDnsProvider() {
    return this.settings ? safeDnsProvider(this.settings) : 'cloudflare';
  }

  get siemProtocolOptions() {
    return siemProtocolOptions();
  }

  get siemProtocol() {
    return siemProtocolValue(this.settings?.wazuhProtocol ?? '');
  }

  loadSettings = async () => {
    if (!this.connected) return;
    const generation = ++this.loadGeneration;
    const revision = this.editRevision;
    this.loading = true;
    this.loadFailed = false;
    try {
      const loaded = await this.client.getSettings();
      if (generation !== this.loadGeneration) return;
      this.savedSettings = { ...loaded };
      if (revision !== this.editRevision) return;
      this.settings = loaded;
      this.savedRevision = this.editRevision;
    } catch (error) {
      if (generation !== this.loadGeneration) return;
      this.loadFailed = true;
      this.host.toast(
        m.settings_toast_error_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    } finally {
      if (generation === this.loadGeneration) this.loading = false;
    }
  };

  saveSettings = async () => {
    if (
      !this.settings ||
      !this.connected ||
      !this.isDirty ||
      !this.settingsFieldsValid ||
      this.saving
    ) {
      return;
    }
    const submittedRevision = this.editRevision;
    const submittedSettings = { ...this.settings };
    this.saving = true;
    try {
      const result = await this.client.updateSettings(submittedSettings);
      if (!result.success) {
        throw new Error(m.settings_error_daemon_rejected());
      }
      const before = this.savedSettings;
      this.savedSettings = submittedSettings;
      this.host.saved?.(before, submittedSettings);
      if (this.editRevision === submittedRevision) {
        this.savedRevision = this.editRevision;
        if (result.notApplied.length > 0) {
          this.host.toast(
            m.settings_toast_not_applied_title(),
            result.notApplied.join('\n'),
            'var(--warn)',
          );
        } else {
          this.host.toast(
            m.settings_toast_saved_title(),
            m.settings_toast_saved_body(),
            'var(--ok)',
          );
        }
        await this.loadSettings();
      }
    } catch (error) {
      this.host.toast(
        m.settings_toast_save_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    } finally {
      this.saving = false;
    }
  };

  patch = <K extends keyof SettingsDto>(key: K, value: SettingsDto[K]) => {
    if (!this.settings) return;
    this.settings = { ...this.settings, [key]: value };
    this.editRevision++;
  };

  /**
   * Puts one field back to its saved value. When nothing else differs from what is saved, the
   * form is clean again and the save bar goes away.
   */
  revertField = <K extends keyof SettingsDto>(key: K) => {
    const saved = this.savedSettings;
    if (!this.settings || !saved) return;
    const settings: SettingsDto = { ...this.settings, [key]: saved[key] };
    this.settings = settings;
    this.editRevision++;
    const keys = Object.keys(saved) as (keyof SettingsDto)[];
    if (keys.every((name) => Object.is(settings[name], saved[name]))) {
      this.savedRevision = this.editRevision;
    }
  };

  /** Typing a new secret replaces the stored one and cancels a pending removal. */
  patchSecret = (valueKey: SecretKey, clearKey: SecretClearKey, value: string) => {
    if (!this.settings) return;
    this.settings = { ...this.settings, [valueKey]: value, [clearKey]: false };
    this.editRevision++;
  };

  /** Asks the daemon to delete the stored secret on the next save. */
  clearSecret = (valueKey: SecretKey, clearKey: SecretClearKey) => {
    if (!this.settings) return;
    this.settings = { ...this.settings, [valueKey]: '', [clearKey]: true };
    this.editRevision++;
  };

  setDnsProtocol = (protocol: string) => {
    if (!this.settings) return;
    this.settings = applyDnsProtocol(this.settings, protocol);
    this.editRevision++;
  };

  onPowerUserToggle = (enabled: boolean) => {
    if (!this.settings) return;
    if (enabled) {
      this.powerUserDialogOpen = true;
      return;
    }
    this.settings = resetPowerUserOptions(this.settings);
    this.editRevision++;
  };

  confirmPowerUser = () => {
    if (!this.settings) return;
    this.settings = { ...this.settings, powerUserSettingsEnabled: true };
    this.editRevision++;
  };
}
