import { RebuffError } from "../interface.js";

/**
 * Parse the score returned by the language model check.
 *
 * The previous implementation used a bare `parseFloat`, which yields `NaN` for any
 * non-numeric completion. Because every comparison against `NaN` is false, a model
 * that answered with prose -- something an attacker can provoke -- scored as "not an
 * injection" and the check silently failed open. Empty completions were worse: they
 * coerced to 0. This parser is strict and fails closed by throwing, so callers cannot
 * mistake "the detector did not work" for "the input is safe".
 */
export function parseModelScore(raw: string | null | undefined): number {
  if (typeof raw !== "string") {
    throw new RebuffError(
      "Language model check returned no content; refusing to treat it as a safe score"
    );
  }

  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new RebuffError(
      "Language model check returned an empty completion; refusing to treat it as a safe score"
    );
  }

  const score = Number(trimmed);
  if (!Number.isFinite(score)) {
    throw new RebuffError(
      `Language model check returned a non-numeric score: ${JSON.stringify(
        trimmed.slice(0, 120)
      )}`
    );
  }
  if (score < 0 || score > 1) {
    throw new RebuffError(
      `Language model check returned a score outside [0, 1]: ${trimmed.slice(0, 120)}`
    );
  }

  return score;
}
