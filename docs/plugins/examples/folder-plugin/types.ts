/** What the core's `Value` becomes once unwrapped. */
export type RawValue = string | number | boolean | string[];

/** A field map as `Configure` delivers it, values unwrapped. */
export type RawConfig = Readonly<Record<string, RawValue | undefined>>;

/** A configuration the plugin refuses. Its message never quotes a value. */
export class ConfigError extends Error {}

/** One line of what `shieldbk doctor` shows. */
export interface Check {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
  /** What to do about it. A failing check without one is worth nothing. */
  readonly remediation: string;
}

/** A trimmed, non-empty string field, or `undefined` when absent. */
export function textField(raw: RawConfig, name: string): string | undefined {
  const value = raw[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value.trim()) throw new ConfigError(`\`${name}\` cannot be empty`);
  return value.trim();
}
