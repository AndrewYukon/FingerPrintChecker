export type FpConfig = {
  publishableKey: string;
  baseUrl?: string;
  powDifficulty?: number;
  integrityProbes?: boolean;
  /** Android only. */
  cloudProjectNumber?: number;
  /** Android only. */
  integrityTimeoutMillis?: number;
  /** iOS only. */
  useAppAttest?: boolean;
  /** iOS only. */
  useDeviceCheck?: boolean;
};

export type FpSuccess = {
  /** Present only when the project enables score details (as do the score fields). */
  visitorId?: string;
  attestation: string;
  eventId?: string;
  trustScore?: number;
  identityConfidence?: number;
  isNew?: boolean;
  trustDeductions: string[];
  shadowDeductions: string[];
  proofStatus?: string;
  expiresIn?: number;
  rulesVersion?: string;
  sealedResult?: string;
  rawJson: string;
};

export type FpFailure = { ok: false; reason: string; httpStatus: number };

export type FpIdentifyResult = ({ ok: true } & FpSuccess) | FpFailure;

export type FpIdentifyOptions = {
  linkedId?: string;
  tags?: Record<string, unknown>;
};
