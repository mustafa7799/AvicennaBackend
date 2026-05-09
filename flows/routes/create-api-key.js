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
          name,
          ratelimit_min = 60,
          permission = "user",
        } = req.body || {};
        
        if (!name || typeof name !== "string") {
          return res.status(400).json({
            success: false,
            message: "Name is required",
          });
        }
        
        const cleanName = name.trim();
        
        if (cleanName.length < 3) {
          return res.status(400).json({
            success: false,
            message: "Name must be at least 3 characters",
          });
        }
        
        if (cleanName.length > 50) {
          return res.status(400).json({
            success: false,
            message: "Name must be less than 50 characters",
          });
        }

      if (!["admin", "user"].includes(permission)) {
        return res.status(400).json({
          success: false,
          message: "Invalid permission",
        });
      }

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
          metadata: {
            "created_by":{
               "platform":"admin_route",
               "api_key_id": auth.key.id || undefined
            }
         }
        })
        .select(`
          id,
          name,
          last_used_at,
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
        key: raw,
        key_data: data,
      });

    } catch (err) {
      console.error(err);

      return res.status(500).json({
        success: false,
        message: "Failed to create API key",
      });
    }
  });

  app.delete("/admin/api-keys/:id", async (req, res) => {
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
  
      const { id } = req.params;
  
      if (!id) {
        return res.status(400).json({
          success: false,
          message: "Key ID required",
        });
      }
  
      /* ===========================
         VERIFY KEY EXISTS
         =========================== */
  
      const { data: existingKey, error: findError } =
        await supabase
          .from("api_auth")
          .select("id, subdomain")
          .eq("id", id)
          .single();
  
      if (findError || !existingKey) {
        return res.status(404).json({
          success: false,
          message: "API key not found",
        });
      }
  
      /* ===========================
         SUBDOMAIN CHECK
         =========================== */
  
      if (existingKey.subdomain !== subdomain) {
        return res.status(403).json({
          success: false,
          message: "Cannot delete API key from another subdomain",
        });
      }
  
      /* ===========================
         HARD DELETE
         =========================== */
  
      const { error: deleteError } = await supabase
        .from("api_auth")
        .delete()
        .eq("id", id);
  
      if (deleteError) {
        console.error(deleteError);
  
        return res.status(500).json({
          success: false,
          message: deleteError.message,
        });
      }
  
      return res.status(200).json({
        success: true,
        message: "API key deleted",
      });
  
    } catch (err) {
      console.error(err);
  
      return res.status(500).json({
        success: false,
        message: "Failed to delete API key",
      });
    }
  });
}