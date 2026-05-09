import crypto from "crypto";
import { supabase } from "../../lib/supabase-client.js";
import { authorizeApiRequest } from "../routes.js";

function generateApiKey() {
  const secret = process.env.API_KEY_HASH_SECRET;

  if (!secret) {
    throw new Error("API_KEY_HASH_SECRET not defined");
  }

  const raw =
    "avcna_sk_" + crypto.randomBytes(32).toString("hex");

  const hash = crypto
    .createHmac("sha256", secret)
    .update(raw)
    .digest("hex");

  return { raw, hash };
}

export function registerAdminApiKeyRoutes(app) {
  app.post("/admin/api-keys", async (req, res) => {
    try {
      const host = req.headers.host.split(":")[0];
      const subdomain = host.split(".")[0];

      if (!subdomain || subdomain === "www") {
        return res.status(400).json({
          success: false,
          message: "Missing or invalid subdomain",
        });
      }

      /* ===========================
         AUTH (ADMIN REQUIRED)
         =========================== */

      const auth = await authorizeApiRequest(
        req,
        subdomain,
        "admin"
      );

      if (!auth.ok) {
        return res.status(auth.status).json({
          success: false,
          message: auth.message,
        });
      }

      /* ===========================
         BODY
         =========================== */

      const {
        name = "Admin API Key",
        ratelimit_min = 60,
        permission = "admin",
      } = req.body || {};

      const { raw, hash } = generateApiKey();

      const { data, error } = await supabase
        .from("api_auth")
        .insert({
          owner_id: auth.key.owner_id,
          subdomain,
          name,
          key_hash: hash,
          ratelimit_min,
          permission,
        })
        .select(`
          id,
          name,
          last_used_at,
          revoked,
          created_at,
          ratelimit_min,
          permission
        `)
        .single();

      if (error) {
        console.error(error);

        return res.status(500).json({
          success: false,
          message: error.message,
        });
      }

      return res.status(201).json({
        success: true,
        key: data,
        plaintext: raw,
      });

    } catch (err) {
      console.error(err);

      return res.status(500).json({
        success: false,
        message: "Failed to create API key",
      });
    }
  });
}