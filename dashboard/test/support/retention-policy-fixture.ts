// SPDX-License-Identifier: AGPL-3.0-only

/** A #88 effective-policy payload covering every `source`. */
export function category(overrides: Record<string, unknown> = {}) {
  return {
    unit: "days",
    effective: 30,
    source: "default",
    override: null,
    platform_default: 30,
    minimum: 1,
    maximum: 3650,
    forever_allowed: false,
    ...overrides,
  };
}

export function policyPayload(overrides: Record<string, unknown> = {}) {
  return {
    client_id: "client-1",
    version: 3,
    can_edit: true,
    set_by: "admin@example.test",
    updated_at: "2026-11-20T10:00:00+00:00",
    pruning_suspended: false,
    categories: {
      telemetry_days: category(),
      command_output_days: category({ effective: 90, platform_default: 90 }),
      command_record_days: category({
        effective: 400, source: "tenant", override: 400, platform_default: 0, minimum: 30,
      }),
      inventory_history_per_section: category({
        unit: "count", effective: 1000, source: "ceiling", override: 5000,
        platform_default: 50, maximum: 1000,
      }),
      alert_days: category({
        effective: 0, source: "tenant", override: 0, platform_default: 0, minimum: 30,
        maximum: 0, forever_allowed: true,
      }),
      notification_days: category({
        effective: 7, source: "floor", override: 3, platform_default: 0, minimum: 7,
      }),
      evidence_default_days: category({
        effective: 2555, platform_default: 2555, minimum: 2555, maximum: 0,
      }),
    },
    ...overrides,
  };
}
