/**
 * AI adapter layer (Phase 12).
 *
 * Airlock itself never talks to an AI service. An adapter is the way
 * protected text reaches an AI tool, and an AI tool's response comes back
 * to be restored on this device. Adapters accept only `OutboundText`, which
 * can be made only from a `text.protect` result whose outbound check passed
 * (or, after a review, was explicitly acknowledged), so a provider can never
 * receive unprotected text by mistake.
 *
 * The built-in adapter is the clipboard: the person pastes the protected
 * text into the AI tool of their choice and pastes the response back. Other
 * adapters (for example a provider API called by the host) can be added
 * without changing the privacy engine.
 */
import type { Platform } from "../engine/platform";
import type { ProtectTextResult } from "../engine/types";

declare const checked: unique symbol;

/** Protected text that passed the outbound check. */
export type OutboundText = string & { readonly [checked]: true };

export interface AiAdapter {
  readonly id: string;
  readonly label: string;
  send(text: OutboundText): Promise<void>;
}

/** The text that may leave the device, or null if it may not. */
export function outboundText(result: ProtectTextResult, acknowledged = false): OutboundText | null {
  if (result.withheld || result.text === null || result.check === null) return null;
  const { status } = result.check;
  if (status === "safe" || (status === "review" && acknowledged)) return result.text as OutboundText;
  return null;
}

export function clipboardAdapter(platform: Platform): AiAdapter {
  return {
    id: "clipboard",
    label: "Copy for AI",
    send: (text) => platform.writeClipboard(text),
  };
}
