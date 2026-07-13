import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchMe } from "@/lib/api";

export default function ProtectedRoute({ children }) {
  const [status, setStatus] = useState("checking"); // checking | ok | denied
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    fetchMe()
      .then(() => active && setStatus("ok"))
      .catch(() => {
        if (!active) return;
        setStatus("denied");
        navigate("/login", { replace: true });
      });
    return () => {
      active = false;
    };
  }, [navigate]);

  if (status === "checking") {
    return (
      <div
        className="min-h-screen flex items-center justify-center bg-[#050505] text-white"
        data-testid="auth-verifying"
      >
        <div className="font-mono text-sm text-[#888] flex items-center gap-3">
          <span className="w-2.5 h-2.5 rounded-full bg-[#00F5A0] animate-pulse" />
          Verifying session…
        </div>
      </div>
    );
  }
  if (status !== "ok") return null;
  return children;
}
