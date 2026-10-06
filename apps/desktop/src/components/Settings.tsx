import { useCallback, useEffect, useState, type FormEvent } from "react";

import { usePlatform } from "../engine/PlatformContext";
import {
  toEngineError,
  type CategoryGroup,
  type EngineError,
  type EntityTypeInfo,
  type LicenseStatus,
  type MaskStyle,
  type PolicyAction,
  type Profile,
  type RuleKind,
  type RuleList,
} from "../engine/types";
import { ErrorNotice } from "./ErrorNotice";
import { ACTION_LABELS, CATEGORY_LABELS } from "./FindingsReport";

const KIND_LABELS: Record<RuleKind, string> = {
  normalized: "Ignore case, accents and spacing",
  case_insensitive: "Ignore case",
  exact: "Exact text",
  regex: "Pattern (regular expression)",
};

export const STYLE_LABELS: Record<MaskStyle, string> = {
  typed_placeholder: "Placeholder by type",
  placeholder: "Plain placeholder",
  synthetic: "Fake value",
  partial: "Partly hidden",
};

const PROFILE_ACTIONS: PolicyAction[] = ["MASK", "REDACT", "GENERALIZE", "BLOCK", "ALLOW"];
const GROUP_ORDER: CategoryGroup[] = [
  "CREDENTIALS",
  "GOVERNMENT",
  "FINANCIAL",
  "PERSONAL",
  "BUSINESS",
  "INTELLECTUAL_PROPERTY",
  "OTHER",
];

function count(n: number, one: string): string {
  return `${n} ${n === 1 ? one : `${one}s`}`;
}

/** Runs one settings change and reports failures in place. */
function useChange(onChanged: () => void) {
  const [error, setError] = useState<EngineError | null>(null);
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async <T,>(job: () => Promise<T>): Promise<T | undefined> => {
      setBusy(true);
      setError(null);
      try {
        const result = await job();
        onChanged();
        return result;
      } catch (err) {
        setError(toEngineError(err));
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [onChanged],
  );
  return { error, setError, busy, run };
}

function RulesSection({ onChanged }: { onChanged: () => void }) {
  const platform = usePlatform();
  const [list, setList] = useState<RuleList | null>(null);
  const [pattern, setPattern] = useState("");
  const [kind, setKind] = useState<RuleKind>("normalized");
  const [category, setCategory] = useState("CONFIDENTIAL_TERM");
  const [action, setAction] = useState<PolicyAction | "">("");
  const { error, setError, busy, run } = useChange(onChanged);

  const reload = useCallback(async () => {
    try {
      setList(await platform.listRules());
    } catch (err) {
      setError(toEngineError(err));
    }
  }, [platform, setError]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const add = async (event: FormEvent) => {
    event.preventDefault();
    if (!pattern.trim()) return;
    const created = await run(() =>
      platform.createRule({ kind, pattern, category_id: category, action: action === "" ? null : action }),
    );
    if (created) {
      setPattern("");
      await reload();
    }
  };

  const categoryLabel = (id: string) => list?.categories.find((c) => c.id === id)?.label ?? id;

  return (
    <section className="report settings__section" aria-labelledby="rules-title">
      <header className="report__head">
        <h2 id="rules-title">Company rules</h2>
        <span className="report__meta">{list ? count(list.rules.length, "rule") : "Loading…"}</span>
      </header>
      <p className="report__foot">
        Words and patterns that are confidential to your company, such as project names or client codes. Airlock
        protects them in every document. Rules stay on this device.
      </p>
      <form className="rule-form" onSubmit={(e) => void add(e)}>
        <label className="rule-form__pattern">
          <span className="field__label">Word, phrase or pattern</span>
          <input
            type="text"
            value={pattern}
            maxLength={2000}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setPattern(e.target.value)}
          />
        </label>
        <label>
          <span className="field__label">Match</span>
          <select value={kind} onChange={(e) => setKind(e.target.value as RuleKind)}>
            {(list?.kinds ?? (Object.keys(KIND_LABELS) as RuleKind[])).map((k) => (
              <option key={k} value={k}>
                {KIND_LABELS[k] ?? k}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="field__label">Category</span>
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            {(list?.categories ?? []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="field__label">Action</span>
          <select value={action} onChange={(e) => setAction(e.target.value as PolicyAction | "")}>
            <option value="">As the profile decides</option>
            {(["MASK", "REDACT", "BLOCK"] as PolicyAction[]).map((a) => (
              <option key={a} value={a}>
                {ACTION_LABELS[a]}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className="primary" disabled={busy || !pattern.trim() || !list}>
          Add Rule
        </button>
      </form>
      {error && <ErrorNotice error={error} aboutFile={false} />}
      {list && list.rules.length > 0 && (
        <ul className="rules" aria-label="Saved company rules">
          {list.rules.map((rule) => (
            <li key={rule.id} className="rules__item" data-enabled={rule.enabled}>
              <span className="rules__main">
                <code className="rules__pattern">{rule.pattern}</code>
                <span className="report__group">
                  {KIND_LABELS[rule.kind]} · {categoryLabel(rule.category_id)}
                  {rule.action ? ` · ${ACTION_LABELS[rule.action]}` : ""}
                </span>
              </span>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  disabled={busy}
                  onChange={(e) => {
                    const enabled = e.target.checked;
                    void run(() => platform.updateRule(rule.id, { enabled })).then((r) => r && reload());
                  }}
                />
                <span>{rule.enabled ? "On" : "Off"}</span>
              </label>
              <button
                type="button"
                className="ghost"
                disabled={busy}
                aria-label={`Delete rule ${rule.pattern}`}
                onClick={() => void run(() => platform.deleteRule(rule.id)).then(() => reload())}
              >
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ProfilesSection({ onChanged }: { onChanged: () => void }) {
  const platform = usePlatform();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [types, setTypes] = useState<EntityTypeInfo[]>([]);
  const [selected, setSelected] = useState<string>("");
  const { error, setError, busy, run } = useChange(onChanged);

  const reload = useCallback(
    async (select?: string) => {
      try {
        const list = await platform.listProfiles();
        setProfiles(list.profiles);
        setTypes(list.entity_types ?? []);
        setSelected((current) => select ?? (list.profiles.some((p) => p.id === current) ? current : list.default_id));
      } catch (err) {
        setError(toEngineError(err));
      }
    },
    [platform, setError],
  );

  useEffect(() => {
    void reload();
  }, [reload]);

  const profile = profiles.find((p) => p.id === selected);
  const replace = (updated: Profile | undefined) => {
    if (updated) setProfiles((all) => all.map((p) => (p.id === updated.id ? updated : p)));
  };

  const duplicate = async () => {
    if (!profile) return;
    const created = await run(() => platform.createProfile(`${profile.name} (copy)`, profile.id));
    if (created) await reload(created.id);
  };

  const groups = GROUP_ORDER.map((group) => ({
    group,
    rows: types.filter((t) => t.category === group),
  })).filter((g) => g.rows.length > 0);

  return (
    <section className="report settings__section" aria-labelledby="profiles-title">
      <header className="report__head">
        <h2 id="profiles-title">Privacy profiles</h2>
      </header>
      <p className="report__foot">
        A profile decides what happens to each kind of data. Built-in profiles can't be changed: duplicate one to make
        your own. Mask styles: a typed placeholder such as [EMAIL_1], a plain [MASKED_1], a realistic fake value, or
        partly hidden (for example the last 4 digits; this one can't be turned back into the original).
      </p>
      <div className="profile-bar">
        <label className="field">
          <span className="field__label">Profile</span>
          <select value={selected} onChange={(e) => setSelected(e.target.value)} aria-label="Profile to edit">
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.default ? " (default)" : ""}
              </option>
            ))}
          </select>
        </label>
        <span className="profile-bar__actions">
          <button type="button" className="ghost" disabled={busy || !profile} onClick={() => void duplicate()}>
            Duplicate
          </button>
          {profile && !profile.default && (
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => void run(() => platform.setDefaultProfile(profile.id)).then(() => reload())}
            >
              Make Default
            </button>
          )}
          {profile && !profile.builtin && (
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => void run(() => platform.deleteProfile(profile.id)).then(() => reload())}
            >
              Delete
            </button>
          )}
        </span>
      </div>
      {error && <ErrorNotice error={error} aboutFile={false} />}
      {profile && !profile.builtin && (
        <label className="field">
          <span className="field__label">Name</span>
          <input
            key={profile.id}
            type="text"
            defaultValue={profile.name}
            maxLength={200}
            aria-label="Profile name"
            onBlur={(e) => {
              const name = e.target.value.trim();
              if (name && name !== profile.name) void run(() => platform.updateProfile(profile.id, { name })).then(replace);
            }}
          />
        </label>
      )}
      {profile && (
        <table className="profile-table" aria-label={`What ${profile.name} does`}>
          <thead>
            <tr>
              <th scope="col">Data</th>
              <th scope="col">Action</th>
              <th scope="col">Mask style</th>
            </tr>
          </thead>
          {groups.map(({ group, rows }) => (
            <tbody key={group}>
              <tr className="profile-table__group">
                <th scope="rowgroup" colSpan={3}>
                  {CATEGORY_LABELS[group]}
                </th>
              </tr>
              {rows.map((t) => {
                const entry = profile.actions[t.id];
                if (!entry) return null;
                const locked = profile.builtin || busy;
                return (
                  <tr key={t.id}>
                    <th scope="row">{t.label}</th>
                    <td>
                      <select
                        aria-label={`Action for ${t.label}`}
                        value={entry.action}
                        disabled={locked}
                        onChange={(e) => {
                          const value = e.target.value as PolicyAction;
                          void run(() => platform.updateProfile(profile.id, { actions: { [t.id]: value } })).then(
                            replace,
                          );
                        }}
                      >
                        {PROFILE_ACTIONS.filter((a) => a !== "GENERALIZE" || t.generalizable).map((a) => (
                          <option key={a} value={a}>
                            {ACTION_LABELS[a]}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      {entry.action === "MASK" ? (
                        <select
                          aria-label={`Mask style for ${t.label}`}
                          value={entry.style}
                          disabled={locked}
                          onChange={(e) => {
                            const value = e.target.value as MaskStyle;
                            void run(() => platform.updateProfile(profile.id, { styles: { [t.id]: value } })).then(
                              replace,
                            );
                          }}
                        >
                          {(Object.keys(STYLE_LABELS) as MaskStyle[])
                            .filter((s) => s !== "partial" || t.category !== "CREDENTIALS")
                            .map((s) => (
                              <option key={s} value={s}>
                                {STYLE_LABELS[s]}
                              </option>
                            ))}
                        </select>
                      ) : (
                        <span className="report__group">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          ))}
        </table>
      )}
    </section>
  );
}

function AllowListSection({ onChanged }: { onChanged: () => void }) {
  const platform = usePlatform();
  const [saved, setSaved] = useState<number | null>(null);
  const { error, setError, busy, run } = useChange(onChanged);

  useEffect(() => {
    platform
      .allowListCount()
      .then(setSaved)
      .catch((err: unknown) => setError(toEngineError(err)));
  }, [platform, setError]);

  return (
    <section className="report settings__section" aria-labelledby="allow-title">
      <header className="report__head">
        <h2 id="allow-title">Values marked "not sensitive"</h2>
        <span className="report__meta">{saved === null ? "Loading…" : count(saved, "value")}</span>
      </header>
      <p className="report__foot">
        Airlock no longer flags these values. Only a one-way fingerprint of each value is kept, protected by your
        Windows account, so the list cannot be read back.
      </p>
      {error && <ErrorNotice error={error} aboutFile={false} />}
      <button
        type="button"
        className="ghost settings__clear"
        disabled={busy || !saved}
        onClick={() => void run(() => platform.clearAllowList()).then(() => setSaved(0))}
      >
        Forget All
      </button>
    </section>
  );
}

function LicenseSection() {
  const platform = usePlatform();
  const [status, setStatus] = useState<LicenseStatus | null>(null);
  const [pasting, setPasting] = useState(false);
  const [text, setText] = useState("");
  const [key, setKey] = useState("");
  const [copied, setCopied] = useState(false);
  // Licence changes don't affect scans, so they never trigger a refresh.
  const { error, setError, busy, run } = useChange(useCallback(() => undefined, []));

  useEffect(() => {
    platform
      .licenseStatus()
      .then(setStatus)
      .catch((err: unknown) => setError(toEngineError(err)));
  }, [platform, setError]);

  const apply = async (job: () => Promise<LicenseStatus>) => {
    const next = await run(job);
    if (next) {
      setStatus(next);
      setPasting(false);
      setText("");
      setKey("");
    }
  };

  const license = status?.license;
  return (
    <section className="report settings__section" aria-labelledby="license-title">
      <header className="report__head">
        <h2 id="license-title">Licence</h2>
        <span className="report__meta">Checked on this device</span>
      </header>
      {status?.state === "licensed" && license ? (
        <div className="license__card">
          <p className="license__name">Licensed to {license.customer}</p>
          <p className="report__structure">
            Lifetime licence · {license.seats === 1 ? "1 seat" : `${license.seats} seats`} · issued{" "}
            {license.issued_at.slice(0, 10)}
            {license.updates_until ? ` · updates until ${license.updates_until}` : ""}
            {license.bound ? " · activated on this computer" : ""}
          </p>
        </div>
      ) : status?.state === "invalid" && status.problem ? (
        <ErrorNotice error={status.problem} aboutFile={false} />
      ) : (
        <p className="report__foot">No licence is installed. Every feature is available.</p>
      )}
      {error && <ErrorNotice error={error} aboutFile={false} />}

      {status?.state !== "licensed" && (
        <>
          <div className="license__actions">
            <button type="button" className="ghost" disabled={busy} onClick={() => void apply(platform.importLicenseFile)}>
              Import Licence File…
            </button>
            <button type="button" className="ghost" disabled={busy} onClick={() => setPasting(!pasting)}>
              Paste Licence…
            </button>
          </div>
          {pasting && (
            <div className="license__paste">
              <label htmlFor="license-text" className="field__label">
                Paste the licence from your e-mail
              </label>
              <textarea
                id="license-text"
                rows={4}
                spellCheck={false}
                value={text}
                maxLength={64 * 1024}
                onChange={(e) => setText(e.target.value)}
              />
              <button
                type="button"
                className="primary"
                disabled={busy || !text.trim()}
                onClick={() => void apply(() => platform.importLicenseText(text))}
              >
                Install Licence
              </button>
            </div>
          )}
          {status?.activation_available && (
            <form
              className="license__activate"
              onSubmit={(e) => {
                e.preventDefault();
                void apply(() => platform.activateLicense(key));
              }}
            >
              <label htmlFor="license-key" className="field__label">
                Or activate online with your licence key
              </label>
              <div className="license__key">
                <input
                  id="license-key"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="ALK-XXXXX-XXXXX-XXXXX-XXXXX"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                />
                <button type="submit" className="ghost" disabled={busy || !key.trim()}>
                  Activate
                </button>
              </div>
              <p className="report__foot">
                Activation sends only the key, this computer's machine code and the app version. Your documents never
                leave this device.
              </p>
            </form>
          )}
        </>
      )}

      {status && (
        <p className="license__machine">
          <span>
            Machine code <code>{status.machine_code}</code>
          </span>
          <button
            type="button"
            className="link"
            onClick={() =>
              void platform
                .writeClipboard(status.machine_code)
                .then(() => setCopied(true))
                .catch(() => undefined)
            }
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </p>
      )}
      {status?.state !== "unlicensed" && (
        <button
          type="button"
          className="ghost settings__clear"
          disabled={busy}
          onClick={() => void apply(platform.removeLicense)}
        >
          Remove Licence
        </button>
      )}
    </section>
  );
}

/**
 * Company rules, privacy profiles and remembered decisions. Everything here
 * is stored on this device only. `onClose(changed)` lets the caller refresh
 * an open scan with the new settings.
 */
export function Settings({ onClose }: { onClose: (changed: boolean) => void }) {
  const [changed, setChanged] = useState(false);
  const markChanged = useCallback(() => setChanged(true), []);
  return (
    <div className="settings">
      <header className="settings__head">
        <h1>Settings</h1>
        <button type="button" className="ghost" onClick={() => onClose(changed)}>
          Done
        </button>
      </header>
      <RulesSection onChanged={markChanged} />
      <ProfilesSection onChanged={markChanged} />
      <AllowListSection onChanged={markChanged} />
      <LicenseSection />
    </div>
  );
}
