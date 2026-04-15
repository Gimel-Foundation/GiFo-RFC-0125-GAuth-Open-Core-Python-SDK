import { Link, useLocation } from "wouter";
import { LayoutDashboard, FileText, Users, Key, LogOut, Map } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { useHealthCheck, useMgmtHealth } from "@workspace/api-client-react";
import { Button } from "@/components/ui/button";

export function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { callerIdentity, logout } = useAuth();
  
  const { data: health } = useHealthCheck();
  const { data: mgmtHealth } = useMgmtHealth();

  const isHealthy = health?.status === "ok" && mgmtHealth?.status === "ok";

  const navItems = [
    { href: "/", label: "Overview", icon: LayoutDashboard },
    { href: "/mandates", label: "Mandates", icon: FileText },
    { href: "/poa-map", label: "PoA Map", icon: Map },
    { href: "/profiles", label: "Profiles", icon: Users },
    { href: "/credentials", label: "Credentials", icon: Key },
  ];

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {/* Sidebar */}
      <div className="w-64 border-r border-border bg-sidebar flex flex-col">
        <div className="h-14 border-b border-border flex items-center px-4 gap-2 text-primary font-bold tracking-tight">
          <img src={`${import.meta.env.BASE_URL}gimel-logo.png`} alt="Gimel" className="h-6 w-6 rounded-full ring-1 ring-white/20" />
          <span className="uppercase tracking-widest text-sm">GAuth Control</span>
        </div>
        
        <div className="flex-1 overflow-y-auto py-4">
          <nav className="space-y-1 px-2">
            {navItems.map((item) => {
              const isActive = location === item.href || (item.href !== "/" && location.startsWith(item.href));
              return (
                <Link key={item.href} href={item.href}>
                  <div className={`flex items-center gap-3 px-3 py-2 text-sm font-mono cursor-pointer transition-colors ${isActive ? 'bg-primary/10 text-primary border-l-2 border-primary' : 'text-muted-foreground hover:bg-secondary hover:text-foreground border-l-2 border-transparent'}`}>
                    <item.icon className="h-4 w-4" />
                    {item.label}
                  </div>
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="p-4 border-t border-border space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-muted-foreground">System Status</span>
              <div className="flex items-center gap-1.5">
                <div className={`h-2 w-2 rounded-full ${isHealthy ? 'bg-emerald-500' : 'bg-destructive animate-pulse'}`} />
                <span className={isHealthy ? 'text-emerald-500' : 'text-destructive'}>
                  {isHealthy ? 'ONLINE' : 'DEGRADED'}
                </span>
              </div>
            </div>
            {mgmtHealth && (
              <div className="text-[10px] text-muted-foreground font-mono flex justify-between">
                <span>MGMT API</span>
                <span>v{mgmtHealth.mgmt_version}</span>
              </div>
            )}
          </div>
          
          <div className="pt-4 border-t border-border">
            <div className="text-xs font-mono text-muted-foreground mb-2 truncate" title={callerIdentity}>
              ID: {callerIdentity}
            </div>
            <Button variant="outline" size="sm" className="w-full font-mono text-xs justify-start rounded-none" onClick={logout}>
              <LogOut className="h-3 w-3 mr-2" />
              Terminate Session
            </Button>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <main className="flex-1 overflow-y-auto p-6 md:p-8">
          <div className="max-w-6xl mx-auto">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}