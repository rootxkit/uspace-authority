import noJsxLiterals from "./no-jsx-literals.mjs";
import noServerRoutes from "./no-server-routes.mjs";

/** This repository's web/ rules, registered as `authority/...`. */
export default {
  meta: { name: "uspace-authority-web" },
  rules: {
    "no-jsx-literals": noJsxLiterals,
    "no-server-routes": noServerRoutes,
  },
};
