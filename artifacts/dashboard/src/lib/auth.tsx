import React, { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { setAuthTokenGetter } from "@workspace/api-client-react";

interface AuthState {
  apiSecret: string;
  callerIdentity: string;
  isAuthenticated: boolean;
  login: (secret: string, identity: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

async function computeBearerToken(secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode("gauth-mgmt-v1"));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [apiSecret, setApiSecret] = useState<string>(() => localStorage.getItem("gauth_api_secret") || "");
  const [callerIdentity, setCallerIdentity] = useState<string>(() => localStorage.getItem("gauth_caller_identity") || "");

  const isAuthenticated = Boolean(apiSecret && callerIdentity);

  useEffect(() => {
    if (apiSecret) {
      setAuthTokenGetter(async () => await computeBearerToken(apiSecret));
    } else {
      setAuthTokenGetter(null);
    }
  }, [apiSecret]);

  useEffect(() => {
    const originalFetch = window.fetch;
    window.fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      if (callerIdentity) {
        headers.set("X-Caller-Identity", callerIdentity);
      }
      return originalFetch(input, { ...init, headers });
    };
    return () => {
      window.fetch = originalFetch;
    };
  }, [callerIdentity]);

  const login = (secret: string, identity: string) => {
    localStorage.setItem("gauth_api_secret", secret);
    localStorage.setItem("gauth_caller_identity", identity);
    setApiSecret(secret);
    setCallerIdentity(identity);
  };

  const logout = () => {
    localStorage.removeItem("gauth_api_secret");
    localStorage.removeItem("gauth_caller_identity");
    setApiSecret("");
    setCallerIdentity("");
  };

  return (
    <AuthContext.Provider value={{ apiSecret, callerIdentity, isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
