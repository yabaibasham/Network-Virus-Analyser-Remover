import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, Lock } from "lucide-react";
import { fetchMe } from "@/lib/api";

export default function Login() {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    // If already authenticated, skip straight to the console.
    fetchMe()
      .then(() => navigate("/dashboard"))
      .catch(() => setChecking(false));
  }, [navigate]);

  const login = () => {
    // REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
    const redirectUrl = window.location.origin + "/dashboard";
    window.location.href = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`;
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#050505] text-white relative overflow-hidden">
      <div className="radar-sweep" style={{ opacity: 0.25 }} />
      <div
        className="relative z-[2] w-full max-w-md border border-[#222] bg-[#0a0a0a] p-8 fade-up"
        data-testid="login-card"
      >
        <div className="flex items-center gap-3 mb-6">
          <ShieldAlert size={26} strokeWidth={1.5} className="text-white" />
          <div className="leading-tight">
            <div className="font-display font-bold text-lg tracking-tight">
              SENTINELGRID<span className="text-[#FF3B30]">/</span>
              <span className="text-[#888] font-mono text-xs">CORE</span>
            </div>
            <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-[#666]">
              SECURE OPERATIONS CONSOLE
            </div>
          </div>
        </div>

        <p className="text-[#aaa] text-sm mb-6 leading-relaxed">
          Authentication is required to access the console. Sign in with your Google
          account to reach the fleet, scanner, network map and remediation tools.
        </p>

        {checking ? (
          <div className="font-mono text-xs text-[#666]">checking existing session…</div>
        ) : (
          <button
            data-testid="google-login-btn"
            onClick={login}
            className="w-full flex items-center justify-center gap-3 bg-white text-black hover:bg-[#00F5A0] transition-colors h-11 font-mono text-xs uppercase tracking-[0.2em]"
          >
            <Lock size={14} strokeWidth={2} />
            Sign in with Google
          </button>
        )}

        <div className="mt-6 border-t border-[#222] pt-4 text-[10px] font-mono uppercase tracking-[0.15em] text-[#555] leading-relaxed">
          Consent-based defensive platform. Access is logged. Use only on assets you
          own or are authorised to monitor.
        </div>
      </div>
    </div>
  );
}
