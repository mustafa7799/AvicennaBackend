import LZString from "lz-string";
import { supabase } from "../lib/supabase-client.js";
import { runFlow } from "./executor.js";
import cors from "cors";
import express from "express";

/* ===========================
   AUTH + RATE LIMIT CACHES
   =========================== */

const AUTH_CACHE_TTL = 60_000; // 1 min
const authConfigCache = new Map(); // subdomain -> { ts, requiresAuth, ratelimit }
const rateLimitBuckets = new Map(); // key:endpoint -> { count, resetAt }

const API_KEY_CACHE_TTL = 60_000; // 1 min
const apiKeyCache = new Map(); // hash -> { ts, data }

/* ===========================
   AUTH HELPER (cached)
   =========================== */

async function getAuthConfig(subdomain) {
  const cached = authConfigCache.get(subdomain);
  const now = Date.now();

  if (cached && now - cached.ts < AUTH_CACHE_TTL) {
    return cached;
  }

  // Get the subdomain's auth setting and default ratelimit from any key
  const { data: userSettings, error: settingsError } = await supabase
    .from("user_settings")
    .select("authentication_enabled")
    .eq("name", subdomain)
    .single();

  if (settingsError) throw settingsError;

  // Optional: grab a sample ratelimit from any non-revoked key
  const { data: keysData, error: keysError } = await supabase
    .from("api_auth")
    .select("ratelimit_min")
    .eq("subdomain", subdomain)
    .eq("revoked", false)
    .limit(1);

  if (keysError) throw keysError;

  const config = {
    ts: now,
    requiresAuth: userSettings?.authentication_enabled ?? false,
    ratelimit: keysData[0]?.ratelimit_min ?? 60,
  };

  authConfigCache.set(subdomain, config);
  return config;
}  

async function authorizeApiRequest(req, subdomain) {
  const config = await getAuthConfig(subdomain);

  if (!config.requiresAuth) {
    return { ok: true, public: true };
  }

  if (!req.apiAuth) {
    return { ok: false, status: 401, message: "Request unauthorized: API key required" };
  }

  const now = Date.now();
  const cached = apiKeyCache.get(req.apiAuth.hash);
  console.log("API KEY CACHE:", Array.from(apiKeyCache.entries()));
  for (const [key, value] of apiKeyCache) {
    console.log(value.data);
  }

  let data;

  if (cached && now - cached.ts < API_KEY_CACHE_TTL) {
    data = cached.data;
  } else {
    const { data: dbData, error } = await supabase
      .from("api_auth")
      .select("id, subdomain, ratelimit_min")
      .eq("key_hash", req.apiAuth.hash)
      .eq("revoked", false)
      .single();

    if (error || !dbData) {
      return { ok: false, status: 401, message: "Invalid API key" };
    }

    apiKeyCache.set(req.apiAuth.hash, {
      ts: now,
      data: dbData
    });

    data = dbData;
  }

  if (data.subdomain !== subdomain) {
    return {
      ok: false,
      status: 403,
      message: "API key not valid for this subdomain",
    };
  }

  supabase
    .from("api_auth")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", data.id)
    .then(() => {})
    .catch(console.error);

  return { ok: true, key: data };
}

/* ===========================
   RATE LIMITER
   =========================== */

function enforceRateLimit(apiKeyId, endpoint, limit) {
  const now = Date.now();
  const bucketKey = `${apiKeyId}:${endpoint}`;
  const bucket = rateLimitBuckets.get(bucketKey);

  if (!bucket || now > bucket.resetAt) {
    rateLimitBuckets.set(bucketKey, {
      count: 1,
      resetAt: now + 60_000,
    });
    return true;
  }

  if (bucket.count >= limit) return false;

  bucket.count++;
  return true;
}

/* ===========================
   FLOW CACHE (unchanged)
   =========================== */

const CACHE_TTL = 60_000;
const flowCache = new Map();

async function getFlowsForSubdomain(subdomain) {
  const cached = flowCache.get(subdomain);
  const now = Date.now();

  if (cached && now - cached.timestamp < CACHE_TTL) {
    return cached.flows;
  }

  const { data: flows, error } = await supabase
    .from("flows")
    .select("*")
    .eq("subdomain", subdomain);

  if (error) throw error;

  flowCache.set(subdomain, { timestamp: now, flows });
  return flows;
}

/* ===========================
   ROUTES
   =========================== */

export async function registerFlowRoutes(app) {
  app.use(cors({
    origin: "*",
    methods: ["GET","POST","PUT","DELETE","OPTIONS"],
    allowedHeaders: ["Content-Type"]
  }));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.get("/api/ping", (req, res) => {
    res.status(200).json({ success: true, status: 200, message:"🏓 Pong!" });
  });

  const SYSTEM_ROUTES = new Set(["ping", "create-key"]);

  app.all("/api/:endpoint_slug", async (req, res) => {
    const { endpoint_slug } = req.params;
    if (SYSTEM_ROUTES.has(endpoint_slug)) return;

    try {
      const host = req.headers.host.split(":")[0];
      const subdomain = host.split(".")[0];

      if (!subdomain || subdomain === "www") {
        return res.status(400).send("Missing or invalid subdomain");
      }

      /* ===== AUTH ===== */
      const auth = await authorizeApiRequest(req, subdomain);
      if (!auth.ok) {
        return res.status(auth.status).json({
          success: false,
          message: auth.message,
        });
      }

      /* ===== RATE LIMIT ===== */
      if (!auth.public) {
        const allowed = enforceRateLimit(
          auth.key.id,
          endpoint_slug,
          auth.key.ratelimit_min
        );

        if (!allowed) {
          return res.status(429).json({
            success: false,
            message: "Rate limit exceeded",
          });
        }

        req.apiKey = auth.key;
      }

      /* ===== FLOW EXECUTION ===== */
      const flows = await getFlowsForSubdomain(subdomain);
      const row = flows.find(f => f.endpoint_slug === endpoint_slug);
      if (!row) return res.status(404).send("Endpoint not found");

      const decompressed = LZString.decompressFromBase64(
        row.published_tree || row.saved_tree
      );
      if (!decompressed) throw new Error("Decompression failed");

      const flow = JSON.parse(decompressed);

      const expectedMethod = flow?.data?.method || "GET";

      if (req.method !== expectedMethod) {
        return res.status(405).json({
          success: false,
          message: `Method ${req.method} not allowed. Expected ${expectedMethod}`
        });
      }

      const context = {
        variables: {},
        flow: { id: row.id, user_id: row.user_id },
      };
      
      // Method (new, non-breaking)
      context.variables["method"] = req.method;
      
      // Existing behavior (unchanged)
      flow?.data?.queryParams?.forEach(p => {
        context.variables[p.key] = p.default_value ?? "";
      });
      Object.assign(context.variables, req.query);
      
      // Body vars (existing behavior)
      flow?.data?.bodyVars?.forEach(key => {
        context.variables[key] = req.body?.[key] ?? null;
      });
      
      // ✅ NEW: Namespaced variables (additive, no breaking changes)
      
      // Query (namespaced)
      flow?.data?.queryParams?.forEach(p => {
        context.variables[`query.${p.key}`] =
          req.query[p.key] ?? p.default_value ?? null;
      });
      
      // Body (namespaced)
      flow?.data?.bodyVars?.forEach(key => {
        context.variables[`body.${key}`] =
          req.body?.[key] ?? null;
      });

      await runFlow(flow, req, res, context);
    } catch (err) {
      console.error(err);
      if (!res.headersSent) res.status(500).send("Flow execution error");
    }
  });

  app.use((req, res, next) => {
    // If the request starts with /api, skip
    if (req.path.startsWith("/api")) return next();
  
    // Otherwise return your custom HTML
    res.status(200).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Invalid Route | Powered by Avicenna</title>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Faculty+Glyphic&family=Lato:ital,wght@0,100;0,300;0,400;0,700;0,900;1,100;1,300;1,400;1,700;1,900&family=League+Spartan:wght@100..900&family=Newsreader:ital,opsz,wght@0,6..72,200..800;1,6..72,200..800&display=swap');

          .bg {
            background: radial-gradient(
              70% 80% at center 0%,
              rgba(74, 244, 170, 0.15) 3%, 
              rgba(74, 244, 170, 0) 70%,   
              rgba(74, 244, 170, 0) 100%
            );
            color: #fff;
            font-family: sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            flex-direction: column;
            padding: 10px 35%;
          }

          @media (max-width: 1000px) {
            .bg {
              padding: 0 18%;
            }
          }

          h1 {
            font-family: Lato, sans;
            font-weight: 700;
            font-size: 1.5em;
            background-image: linear-gradient(to right bottom, #eeeeee, #bebdbd); /* Whitish to grayish */
            -webkit-background-clip: text; /* For Webkit browsers */
            background-clip: text; /* Standard property */
            -webkit-text-fill-color: transparent; /* For Webkit browsers */
            color: transparent; /* Standard property for fallback */;
            margin: 0;
            text-align: center;
          }

          p {
            color: #c7c7c7;
            font-family: Lato, sans;
            margin: 0;
            text-align: center;
            font-weight: 400;
          }

          kbd {
            background-color: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.074);
            border-radius: 5px;
            padding: 2.5px;
          }

          body {
            background-color: #060606;
            margin: 0;
            font-family: Lato, sans;
          }

          a {
            margin: 0;
            padding: 0;
          }

          .lucide {
            color: white;
            background-image: linear-gradient(to left bottom, oklab(1 0 5.9604645e-8 / 0.1) 0px, rgba(0, 0, 0, 0) 100%);
            padding: 13px;
            margin: 5px;
            border: 2px solid rgba(255, 255, 255, 0.074);
            border-radius: 15px;
            display: inline-block;
            vertical-align: middle;
            margin-bottom: 10px;
          }

          .lucide img {
            height: 30px;
            width: 30px;
            object-fit: contain;
            display: block;
          }
          
          .branding {
            font-family: Lato, sans;
            display: flex;
            gap: 2.5px;
            color: white;
            opacity: 0.7;
            position: relative;
            top: 300px;
            text-decoration: none;
            padding: 7.5px 15px;
            border: 1px solid rgba(255, 255, 255, 0.074);
            border-radius: 10px;
          }

          .branding:hover {
            opacity: 0.5;
          }

          .branding img {
            width: 1.5em;
            height: auto;
            display: inline-block;
            vertical-align: text-top;
          }
        </style>
      </head>
      <body>
          <div class="bg">
            <div class="lucide">
              <img src="data:image/svg+xml;base64,PHN2ZyBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBhdGggZD0iTTEyIDE2aC4wMSIvPjxwYXRoIGQ9Ik0xMiA4djQiLz48cGF0aCBkPSJNMTUuMzEyIDJhMiAyIDAgMCAxIDEuNDE0LjU4Nmw0LjY4OCA0LjY4OEEyIDIgMCAwIDEgMjIgOC42ODh2Ni42MjRhMiAyIDAgMCAxLS41ODYgMS40MTRsLTQuNjg4IDQuNjg4YTIgMiAwIDAgMS0xLjQxNC41ODZIOC42ODhhMiAyIDAgMCAxLTEuNDE0LS41ODZsLTQuNjg4LTQuNjg4QTIgMiAwIDAgMSAyIDE1LjMxMlY4LjY4OGEyIDIgMCAwIDEgLjU4Ni0xLjQxNGw0LjY4OC00LjY4OEEyIDIgMCAwIDEgOC42ODggMnoiLz48L3N2Zz4="></img>
            </div>
            <h1>Whoops, this is an invalid route!</h1>
            <p>You've reached an invalid route on this API. Try double-checking your URL contains <kbd>/api</kbd> and reload the page.</p>


            <a href="https://www.avicenna.dev/?utm_source=invalid_route_api_page" class="branding">
                Powered by <img src="https://i.ibb.co/27hDV9wc/avicenna-api-white-logo-solo.png"></img> Avicenna
            </a>
          </div>
      </body>
      </html>
    `);
  });

  console.log("✅ Dynamic /api/:endpoint_slug route registered");
}
