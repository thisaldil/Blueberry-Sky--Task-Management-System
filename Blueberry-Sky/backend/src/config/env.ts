import dotenv from "dotenv";

dotenv.config();

function required(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    // Fail fast and loud — never silently fall back to an insecure default
    // for a secret. This is especially important for JWT and encryption keys.
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const env = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  isProduction: process.env.NODE_ENV === "production",
  port: Number(process.env.PORT ?? 5000),
  clientUrl: required("CLIENT_URL"),

  mongodbUri: required("MONGODB_URI"),

  jwtAccessSecret: required("JWT_ACCESS_SECRET"),
  jwtRefreshSecret: required("JWT_REFRESH_SECRET"),
  jwtAccessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN ?? "15m",
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? "7d",

  fieldEncryptionKey: required("FIELD_ENCRYPTION_KEY"),
  cookieSecret: required("COOKIE_SECRET"),

  authRateLimitWindowMs: Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS ?? 900000),
  authRateLimitMax: Number(process.env.AUTH_RATE_LIMIT_MAX ?? 10),
};

// Extra guard: the field encryption key must decode to exactly 32 bytes (AES-256).
const keyBuffer = Buffer.from(env.fieldEncryptionKey, "hex");
if (keyBuffer.length !== 32) {
  throw new Error(
    "FIELD_ENCRYPTION_KEY must be a 32-byte value encoded as 64 hex characters. " +
      "Generate one with: openssl rand -hex 32"
  );
}

if (env.isProduction && env.jwtAccessSecret === env.jwtRefreshSecret) {
  throw new Error("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must not be identical.");
}