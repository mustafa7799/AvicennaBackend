import { staticVars } from "./staticVars.js";

/**
 * Resolves a variable path in context, with fallback to defaults from the flow
 * @param {object} context - flow context (e.g., { variables: { name: "Ali" } })
 * @param {string} path - variable path, e.g., 'variables.name' or 'request-1.body.title'
 * @param {object} defaults - fallback defaults (e.g., flow defaults like { name: "Mustapha" })
 * @returns {any} - resolved value
 */
export function resolveVar(context, path, defaults = {}) {
  if (!path) return "";
 console.log("RESOLVE CONTEXT KEYS:", Object.keys(context || {}));
console.log("RESOLVE VARIABLES:", context?.variables);

  const parts = path.split(".");
  let value = context;

  for (let i = 0; i < parts.length; i++) {
    let part = parts[i].trim();
  
    if (i === 0 && part in staticVars && typeof staticVars[part] === "function") {
      const arg = parts[1];
      let evaluatedArg = arg;
      try { evaluatedArg = Function(`"use strict"; return (${arg});`)(); } catch {}
      return staticVars[part](evaluatedArg);
    }
  
    // always check top-level context first
    if (i === 0) {
      // Direct top-level access (existing behavior)
      if (context[part] !== undefined) {
        value = context[part];
        continue;
      }
    
      // ✅ NEW: handle namespaced variables like body.x, query.x
      if ((part === "body" || part === "query") && context.variables) {
        value = context.variables;
        continue;
      }
    }
  
    // then check nested object
    if (value && typeof value === "object") {
      // Direct object access
      if (value[part] !== undefined) {
        value = value[part];
      }
      // ✅ NEW: support body.x / query.x via variables map
      else if (context.variables && value === context.variables) {
        const fullKey = parts.slice(0, i + 1).join(".");
        if (context.variables[fullKey] !== undefined) {
          value = context.variables[fullKey];
        } else {
          return "";
        }
      } else {
        return "";
      }
    }
    else if (i === parts.length - 1 && context.variables && part in context.variables) {
      value = context.variables[part];
    } 
    else if (i === parts.length - 1 && part in defaults) {
      value = defaults[part];
    } 
    else if (i === parts.length - 1 && part in staticVars) {
      const val = staticVars[part];
      value = typeof val === "function" ? val() : val;
    } 
    else {
      return "";
    }
  }

  return value;
}

function expandBracketSyntax(expr) {
  // Matches: something[ inside ]
  // Example: solve[1+2], data[userId], arr[ index ]
  const bracketRegex = /^([^\[\]]+)\[(.+)\]$/;

  const match = expr.match(bracketRegex);
  if (!match) return expr; // no bracket syntax → skip

  const base = match[1];
  const inside = match[2];

  let evaluated;

  // Try number, boolean, null, etc.
  try {
    evaluated = Function(`"use strict"; return (${inside});`)();
  } catch {
    evaluated = inside.trim(); // fallback: treat as string key
  }

  return `${base}.${evaluated}`;
}

/**
 * Interpolates all {varName} placeholders in a string using context,
 * falling back to defaults when the variable is missing.
 * @param {string} template - string containing {vars}
 * @param {object} context - flow context (e.g., { variables: { name: "Ali" } })
 * @param {object} defaults - fallback defaults (e.g., flow defaults like { name: "Mustapha" })
 * @returns {string} - string with variables replaced
 */
export function interpolate(template, context, defaults = {}) {
  if (!template) return "";

  return template.replace(/\{([^}]+)\}/g, (_, expr) => {
    expr = expr.trim();

    // NEW: expand bracket expressions before resolving
    expr = expandBracketSyntax(expr);

    let val = resolveVar(context, expr, defaults);

    if (Array.isArray(val)) return val.join(", ");
    if (val && typeof val === "object") return JSON.stringify(val);

    return val != null ? val : "";
  });
}