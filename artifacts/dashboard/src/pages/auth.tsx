import { useAuth } from "@/lib/auth";
import { useState } from "react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function AuthPage() {
  const { login } = useAuth();
  const [, setLocation] = useLocation();
  const [secret, setSecret] = useState("");
  const [identity, setIdentity] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (secret && identity) {
      login(secret, identity);
      setLocation("/");
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md space-y-8">
        <div className="flex flex-col items-center text-center">
          <img src={`${import.meta.env.BASE_URL}gimel-logo.png`} alt="Gimel Foundation" className="h-16 w-16 mb-4 rounded-md" />
          <h1 className="text-3xl font-bold tracking-tight text-foreground uppercase">GAuth Control Plane</h1>
          <p className="text-muted-foreground mt-2 font-mono text-sm">RESTRICTED ACCESS AREA</p>
        </div>

        <Card className="border-primary/20 bg-card rounded-none">
          <CardHeader>
            <CardTitle className="font-mono text-primary uppercase">Authentication Required</CardTitle>
            <CardDescription className="font-mono text-xs">
              Provide your API Secret and Caller Identity to access the management interface.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="secret" className="font-mono uppercase text-xs">API Secret</Label>
                <Input
                  id="secret"
                  type="password"
                  required
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  className="font-mono rounded-none border-border focus-visible:ring-primary bg-input"
                  placeholder="Enter secret key..."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="identity" className="font-mono uppercase text-xs">Caller Identity</Label>
                <Input
                  id="identity"
                  type="text"
                  required
                  value={identity}
                  onChange={(e) => setIdentity(e.target.value)}
                  className="font-mono rounded-none border-border focus-visible:ring-primary bg-input"
                  placeholder="e.g., admin@gauth.local"
                />
              </div>
              <Button type="submit" className="w-full rounded-none font-mono uppercase tracking-wider">
                Initialize Session
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
