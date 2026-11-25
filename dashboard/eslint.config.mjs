import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

// Route cores written before the shared guard (#280). Migrate one, then drop it here.
const LEGACY_ROUTE_CORES = [
  "admin-sessions",
  "alert-action",
  "approval",
  "assistant",
  "auth",
  "client-site-management",
  "community-packages",
  "email-delivery",
  "emergency-override",
  "maintenance-window",
  "mfa",
  "operator-management",
  "patch-policies",
  "script-library",
  "webhook",
].map((name) => `src/lib/${name}-route-core.ts`);

// GLOSSARY.md: the tenancy term is "client". The API's "tenant" wire values stay.
const TENANT_COPY = "Operator-facing text says \"client\", not \"tenant\" (GLOSSARY.md).";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    files: ["src/lib/*-route-core.ts"],
    ignores: ["src/lib/bff-route-core.ts", ...LEGACY_ROUTE_CORES],
    rules: {
      "no-restricted-imports": ["error", {
        patterns: [{
          group: ["./dashboard-auth-core*", "@/lib/dashboard-auth-core*"],
          importNames: ["isSameOrigin", "requestOrigin"],
          message: "Build route cores on isSameOriginRequest and authorizeSession from ./bff-route-core.ts.",
        }],
      }],
    },
  },
  {
    files: ["src/**/*.tsx"],
    rules: {
      "no-restricted-syntax": ["error",
        { selector: "JSXText[value=/\\btenant/i]", message: TENANT_COPY },
        { selector: "JSXExpressionContainer > Literal[value=/\\btenant/i]", message: TENANT_COPY },
        { selector: "JSXAttribute > Literal[value=/\\btenant/i]", message: TENANT_COPY },
      ],
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
