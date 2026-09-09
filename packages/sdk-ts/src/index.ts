/**
 * @isoc/sdk — TypeScript client for Intelligence SOC
 *
 * Auto-generated types from docs/openapi.yaml; hand-written client wrapper.
 *
 * @example
 * ```ts
 * import { AiSOCClient } from "@isoc/sdk";
 *
 * const client = new AiSOCClient({
 *   baseUrl: "https://your-aisoc.example.com",
 *   token: process.env.AISOC_API_TOKEN,
 * });
 *
 * const alerts = await client.alerts.list({ severity: "critical" });
 * ```
 */

export { AiSOCClient } from "./client.js";
export type { AiSOCClientOptions } from "./client.js";
export * from "./types.js";
