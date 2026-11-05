// Flat ESLint config. Lints package TypeScript and the browser consent script.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "packages/collector/public/**", // browser globals; not type-checked here
      "website/**", // static marketing site (browser JS), not part of the TS packages
      "**/*.mjs",
      "docs/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["packages/*/src/**/*.ts"],
    rules: {
      "no-empty": ["error", { allowEmptyCatch: true }],
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  {
    files: ["website/consent.js"],
    languageOptions: {
      globals: {
        document: "readonly",
        localStorage: "readonly",
        window: "readonly",
      },
    },
  },
);
