import { useListMandates, useMgmtHealth } from "@workspace/api-client-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, ShieldCheck, ShieldAlert, FileText, Clock, AlertTriangle } from "lucide-react";
import { Link } from "wouter";
import { formatDistanceToNow } from "date-fns";

export default function Dashboard() {
  const { data: mandatesData, isLoading } = useListMandates({ limit: 100 });
  const { data: health } = useMgmtHealth();

  const mandates = mandatesData?.items || [];
  
  const stats = {
    total: mandates.length,
    active: mandates.filter(m => m.status === "ACTIVE").length,
    suspended: mandates.filter(m => m.status === "SUSPENDED").length,
    draft: mandates.filter(m => m.status === "DRAFT").length,
    revoked: mandates.filter(m => m.status === "REVOKED").length,
    expired: mandates.filter(m => m.status === "EXPIRED").length,
  };

  const recentMandates = [...mandates].sort((a, b) => 
    new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
  ).slice(0, 5);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "ACTIVE": return "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
      case "DRAFT": return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      case "SUSPENDED": return "bg-amber-500/10 text-amber-500 border-amber-500/20";
      case "REVOKED": return "bg-destructive/10 text-destructive border-destructive/20";
      case "EXPIRED": return "bg-muted text-muted-foreground border-border";
      default: return "bg-secondary text-secondary-foreground border-border";
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1">Global Overview</h1>
        <p className="text-muted-foreground font-mono text-sm">System-wide mandate activity and governance status.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono text-muted-foreground uppercase flex items-center justify-between">
              Total Mandates
              <FileText className="h-4 w-4 text-primary" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{isLoading ? "-" : stats.total}</div>
          </CardContent>
        </Card>
        
        <Card className="bg-card border-border rounded-none shadow-none border-t-2 border-t-emerald-500">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono text-muted-foreground uppercase flex items-center justify-between">
              Active Operations
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-emerald-500">{isLoading ? "-" : stats.active}</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border rounded-none shadow-none border-t-2 border-t-amber-500">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono text-muted-foreground uppercase flex items-center justify-between">
              Suspended / Revoked
              <ShieldAlert className="h-4 w-4 text-amber-500" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-amber-500">{isLoading ? "-" : (stats.suspended + stats.revoked)}</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="col-span-2 bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border pb-4">
            <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Recent Activity
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-8 text-center text-muted-foreground font-mono text-sm">Loading telemetry...</div>
            ) : recentMandates.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground font-mono text-sm">No mandates found in system.</div>
            ) : (
              <div className="divide-y divide-border">
                {recentMandates.map((mandate) => (
                  <div key={mandate.mandate_id} className="p-4 flex items-center justify-between hover:bg-secondary/50 transition-colors">
                    <div className="space-y-1">
                      <div className="flex items-center gap-3">
                        <Link href={`/mandates/${mandate.mandate_id}`} className="font-mono text-primary hover:underline">
                          {mandate.mandate_id.split('-')[0]}...
                        </Link>
                        <Badge variant="outline" className={`rounded-none font-mono text-[10px] ${getStatusColor(mandate.status)}`}>
                          {mandate.status}
                        </Badge>
                      </div>
                      <div className="font-mono text-xs text-muted-foreground">
                        Subject: {mandate.parties.subject} | Profile: {mandate.governance_profile}
                      </div>
                    </div>
                    <div className="text-right space-y-1">
                      <div className="font-mono text-xs text-muted-foreground flex items-center justify-end gap-1">
                        <Clock className="h-3 w-3" />
                        {formatDistanceToNow(new Date(mandate.updated_at), { addSuffix: true })}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div className="p-3 border-t border-border bg-secondary/30 text-center">
              <Link href="/mandates" className="text-xs font-mono text-primary uppercase hover:underline">
                View All Mandates →
              </Link>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border pb-4">
            <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              System Features
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4">
            <div className="space-y-4">
              {health?.feature_flags ? (
                Object.entries(health.feature_flags).map(([key, enabled]) => (
                  <div key={key} className="flex items-center justify-between">
                    <span className="font-mono text-xs uppercase text-muted-foreground">{key.replace('_', ' ')}</span>
                    <Badge variant="outline" className={`rounded-none font-mono text-[10px] ${enabled ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-muted text-muted-foreground'}`}>
                      {enabled ? 'ENABLED' : 'DISABLED'}
                    </Badge>
                  </div>
                ))
              ) : (
                <div className="text-center text-muted-foreground font-mono text-sm py-4">Status unavailable</div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}