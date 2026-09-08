import { defineRailway, preserve, project, service } from "railway/iac";

// Last resort for a per-service CaC repo. Prefer one .railway file for the
// project and drop this if you later combine services into that file.
export const partial = "fiat-verifier";

export default defineRailway(() => {
  const fiat_verifier = service("fiat-verifier", {
    build: {
      builder: "DOCKERFILE",
      dockerfilePath: "Dockerfile",
    },
    deploy: {
      healthcheckPath: "/health",
      healthcheckTimeout: 120,
      restartPolicyType: "ON_FAILURE",
    },
    env: {
      BUYER_RETURN_ORIGINS: preserve(),
      FIAT_DATABASE_URL: preserve(),
      FIAT_LISTEN_ADDR: preserve(),
      FIAT_PAYKIT_SERVER_URL: preserve(),
      FIAT_SETTLEMENT_DELAY_SECONDS: preserve(),
      FIAT_SYNTHESIZED_CONFIRMATIONS: preserve(),
      FIAT_TRUSTED_LOCKS_PUBLIC_KEY: preserve(),
      PAYPAL_CLIENT_ID: preserve(),
      PAYPAL_CLIENT_SECRET: preserve(),
      PAYPAL_WEBHOOK_ID: preserve(),
      PORT: preserve(),
      STRIPE_SECRET_KEY: preserve(),
      STRIPE_WEBHOOK_SECRET: preserve(),
    },
  });
  return project("pubky-marketplace-staging", {
    resources: [fiat_verifier],
  });
});
