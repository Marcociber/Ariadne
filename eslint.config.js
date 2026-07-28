/**
 * ESLint flat config for the frontend.
 *
 * The project deliberately has no npm toolchain, so there is nothing to
 * install permanently. Run it on demand:
 *
 *     npx eslint assets/
 *     npx prettier --check assets/ index.html
 *
 * The same command is what CI runs (.github/workflows/frontend.yml).
 */
export default [
  {
    files: ["assets/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        window: "readonly",
        document: "readonly",
        navigator: "readonly",
        localStorage: "readonly",
        fetch: "readonly",
        Blob: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        TextDecoder: "readonly",
        AbortController: "readonly",
        requestAnimationFrame: "readonly",
        cancelAnimationFrame: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        getComputedStyle: "readonly",
      },
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-undef": "error",
      "prefer-const": "error",
      "no-var": "error",
      eqeqeq: ["error", "smart"],
      // The whole point of the rewrite: keep inline handlers out so a strict
      // Content-Security-Policy stays possible.
      "no-implied-eval": "error",
      "no-eval": "error",
    },
  },
];
