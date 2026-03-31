// flows/logging.js
import { supabase } from "../lib/supabase-client.js";
import { appendFlowAnalytics } from "./analytics.js";

/**
 * Append a log entry to a flow's request_logs JSONB column.
 * Keeps the last 20 entries only.
 */
export async function appendFlowLog(flowId, log) {
  console.log("[appendFlowLog] flowId:", flowId, "log:", log);

  if (!flowId) {
    console.warn("[appendFlowLog] No flowId provided, skipping log");
    return;
  }

  try {
    const { data, error } = await supabase
      .from("flows")
      .select("request_logs")
      .eq("id", flowId)
      .single();

    if (error) {
      console.error("[appendFlowLog] Failed to fetch request_logs:", error);
      return;
    }

    const logs = Array.isArray(data.request_logs) ? data.request_logs : [];
    logs.unshift(log); // newest log first
    const trimmed = logs.slice(0, 20);

    const { error: updateErr } = await supabase
      .from("flows")
      .update({ request_logs: trimmed })
      .eq("id", flowId);

    if (updateErr) {
      console.error("[appendFlowLog] Failed to update request_logs:", updateErr);
    } else {
      console.log("[appendFlowLog] Successfully updated logs");
    }
  } catch (err) {
    console.error("[appendFlowLog] crashed:", err);
  }
}

/**
 * Middleware that attaches start time to each request.
 */
export function trackRequestStart(req, res, next) {
  req._start = Date.now();
  next();
}

/**
 * Middleware that logs /api/* requests based on subdomain + endpoint_slug
 */
export function apiRequestLogger() {
  return (req, res, next) => {
    res.on("finish", async () => {
      const duration = Date.now() - req._start;

      // Extract endpoint slug from /api/ENDPOINT_SLUG
      const match = req.path.match(/^\/api\/([^/]+)/);
      if (!match) {
        console.log("[apiRequestLogger] Path does not match /api/:slug — skipping");
        return;
      }
      const endpoint_slug = match[1];

      // Extract subdomain from host (assumes format SUBDOMAIN.example.com)
      const host = req.headers.host || "";
      const subdomain = host.split(".")[0]; // crude but works for dev: SUBDOMAIN.lvh.me

      if (!subdomain || !endpoint_slug) {
        console.log("[apiRequestLogger] Missing subdomain or endpoint_slug — skipping");
        return;
      }

      console.log("[apiRequestLogger] Looking for flow:", { subdomain, endpoint_slug });

      // Find the flow in Supabase
      const { data: flowData, error } = await supabase
        .from("flows")
        .select("id")
        .eq("subdomain", subdomain)
        .eq("endpoint_slug", endpoint_slug)
        .single();

      if (error || !flowData) {
        console.warn("[apiRequestLogger] No flow found for this subdomain+endpoint:", error);
        return;
      }

      const log = {
        ip: req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || req.ip,
        ts: new Date().toISOString(),
        method: req.method,
        path: req.originalUrl.replace(/^\/api/, ""),
        status: res.statusCode,
        duration,
        ua: req.headers["user-agent"] || "",
      };

      appendFlowLog(flowData.id, log);
      appendFlowAnalytics(flowData.id, res.statusCode);
    });

    next();
  };
}
