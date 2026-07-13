import { useEffect, useRef } from "react";
import { postSession } from "@/lib/api";

// REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
export default function AuthCallback() {
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;
    processed.current = true;
    const match = window.location.hash.match(/session_id=([^&]+)/);
    const sessionId = match ? decodeURIComponent(match[1]) : null;
    (async () => {
      if (sessionId) {
        try {
          await postSession(sessionId);
        } catch (e) {
          // fall through — ProtectedRoute will bounce to /login if this failed
        }
      }
      window.location.replace("/dashboard");
    })();
  }, []);

  return (
    <div
      className="min-h-screen flex items-center justify-center bg-[#050505] text-white"
      data-testid="auth-callback"
    >
      <div className="font-mono text-sm text-[#888] flex items-center gap-3">
        <span className="w-2.5 h-2.5 rounded-full bg-[#00F5A0] animate-pulse" />
        Establishing secure session…
      </div>
    </div>
  );
}
