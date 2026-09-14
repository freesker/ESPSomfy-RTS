// Vérification statique de data/index.js : détecte les identifiants non définis (ReferenceError à
// l'exécution) et le code mort. Lancer : npm run lint
export default [{
  files: ["data/**/*.js"],
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: "script",
    globals: {
      window: "readonly", document: "readonly", navigator: "readonly", location: "readonly",
      XMLHttpRequest: "readonly", WebSocket: "readonly", FormData: "readonly", fetch: "readonly",
      setTimeout: "readonly", clearTimeout: "readonly", setInterval: "readonly", clearInterval: "readonly",
      console: "readonly", CustomEvent: "readonly", Event: "readonly", HTMLElement: "readonly",
      HTMLInputElement: "readonly", HTMLSelectElement: "readonly", Option: "readonly", Blob: "readonly",
      URL: "readonly", DataView: "readonly", Uint8Array: "readonly", Uint32Array: "readonly",
      MouseEvent: "readonly", TouchEvent: "readonly", Node: "readonly", NodeList: "readonly",
      requestAnimationFrame: "readonly", alert: "readonly", confirm: "readonly", DOMParser: "readonly",
      Intl: "readonly", performance: "readonly", getComputedStyle: "readonly", DragEvent: "readonly",
      File: "readonly", FileReader: "readonly", history: "readonly"
    }
  },
  rules: {
    "no-undef": "error",
    "no-redeclare": "error",
    "no-dupe-keys": "error",
    "no-unreachable": "error",
    "no-unused-vars": ["warn", { args: "none" }],
    "no-empty": "warn"
  }
}];
