import { createContext, useCallback, useContext, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api";

const AuthContext = createContext(null);

async function fetchAuthStatus() {
  return apiFetch("/auth/status");
}

export function AuthProvider({ children }) {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["auth-status"],
    queryFn: fetchAuthStatus,
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: Infinity,
  });

  /**
   * Sign in. Pass {username, password} (basic mode) or {api_key} (apikey mode).
   *
   * @param {{username?: string, password?: string, api_key?: string}} credentials
   * @returns {Promise<object>} Login response.
   * @throws {Error} With the backend detail on failure.
   */
  const login = useCallback(async (credentials) => {
    const result = await apiFetch("/auth/login", { method: "POST", body: credentials });
    await qc.invalidateQueries({ queryKey: ["auth-status"] });
    return result;
  }, [qc]);

  /** Sign out, drop cached data, and flip the UI to logged-out immediately. */
  const logout = useCallback(async () => {
    try {
      await apiFetch("/auth/logout", { method: "POST" });
    } finally {
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "auth-status" });
      qc.setQueryData(["auth-status"], (prev) => ({
        ...(prev ?? {}),
        authenticated: false,
        user: null,
      }));
      qc.invalidateQueries({ queryKey: ["auth-status"] });
    }
  }, [qc]);

  const value = useMemo(() => ({
    mode: data?.mode ?? "none",
    isAuthenticated: data?.authenticated ?? false,
    user: data?.user ?? null,
    isWritable: data?.writable ?? true,
    storedUsername: data?.username ?? "",
    hasPassword: data?.has_password ?? false,
    proxyHeader: data?.proxy_header ?? "Remote-User",
    trustedProxies: data?.trusted_proxies ?? [],
    isLoading,
    login,
    logout,
  }), [data, isLoading, login, logout]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within <AuthProvider>");
  }
  return ctx;
}
