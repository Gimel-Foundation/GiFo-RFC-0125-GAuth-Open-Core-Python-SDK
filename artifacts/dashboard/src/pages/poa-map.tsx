import { useListMandates } from "@workspace/api-client-react";
import type { MandateResponse, ToolPolicy, PlatformPermissions } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Lock, Unlock, Eye, ChevronDown, ChevronRight, Globe, Briefcase, Scale, Server } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

function PermissionCard({ mandate }: { mandate: MandateResponse }) {
  const [expanded, setExpanded] = useState(false);

  const coreVerbs = mandate.scope.core_verbs ?? {};
  const platformPerms = mandate.scope.platform_permissions;
  const allowedSectors = mandate.scope.allowed_sectors ?? [];
  const allowedRegions = mandate.scope.allowed_regions ?? [];
  const allowedDecisions = mandate.scope.allowed_decisions ?? [];
  const allowedPaths = mandate.scope.allowed_paths ?? [];
  const deniedPaths = mandate.scope.denied_paths ?? [];

  const allowedVerbs = Object.entries(coreVerbs).filter(([, p]: [string, ToolPolicy]) => p.allowed !== false);
  const deniedVerbs = Object.entries(coreVerbs).filter(([, p]: [string, ToolPolicy]) => p.allowed === false);
  const approvalRequiredVerbs = Object.entries(coreVerbs).filter(([, p]: [string, ToolPolicy]) => p.requires_approval);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "ACTIVE": return "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
      case "DRAFT": return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      case "SUSPENDED": return "bg-amber-500/10 text-amber-500 border-amber-500/20";
      case "REVOKED": return "bg-destructive/10 text-destructive border-destructive/20";
      default: return "bg-muted text-muted-foreground border-border";
    }
  };

  return (
    <Card className="bg-card border-border rounded-none shadow-none">
      <CardHeader
        className="cursor-pointer border-b border-border bg-secondary/10 py-3"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {expanded ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
            <div>
              <div className="font-mono text-sm font-bold text-primary" data-testid={`text-poa-mandate-${mandate.mandate_id}`}>{mandate.mandate_id.split('-')[0]}...</div>
              <div className="font-mono text-xs text-muted-foreground">{mandate.parties.subject}</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className={cn("rounded-none font-mono text-[10px]", getStatusColor(mandate.status))}>
              {mandate.status}
            </Badge>
            <Badge variant="outline" className="rounded-none font-mono text-[10px] text-muted-foreground">
              {mandate.governance_profile}
            </Badge>
          </div>
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="p-4 space-y-4">
          <div>
            <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
              <Unlock className="h-3 w-3 text-emerald-500" /> Allowed Verbs ({allowedVerbs.length})
            </div>
            <div className="flex flex-wrap gap-1.5">
              {allowedVerbs.length > 0 ? allowedVerbs.map(([verb, policy]) => (
                <Badge key={verb} variant="outline" className="rounded-none font-mono text-[10px] text-emerald-500 border-emerald-500/30 bg-emerald-500/5" data-testid={`badge-allowed-${verb}`}>
                  {verb}
                  {(policy as ToolPolicy).max_per_session != null && ` (max:${(policy as ToolPolicy).max_per_session})`}
                </Badge>
              )) : (
                <span className="text-xs font-mono text-muted-foreground">None defined</span>
              )}
            </div>
          </div>

          {deniedVerbs.length > 0 && (
            <div>
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Lock className="h-3 w-3 text-destructive" /> Denied Verbs ({deniedVerbs.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {deniedVerbs.map(([verb]) => (
                  <Badge key={verb} variant="outline" className="rounded-none font-mono text-[10px] text-destructive border-destructive/30 bg-destructive/5">
                    {verb}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {approvalRequiredVerbs.length > 0 && (
            <div>
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Eye className="h-3 w-3 text-amber-500" /> Requires Approval ({approvalRequiredVerbs.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {approvalRequiredVerbs.map(([verb]) => (
                  <Badge key={verb} variant="outline" className="rounded-none font-mono text-[10px] text-amber-500 border-amber-500/30 bg-amber-500/5">
                    {verb}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {allowedDecisions.length > 0 && (
            <div className="border-t border-border pt-3">
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Scale className="h-3 w-3" /> Allowed Decisions ({allowedDecisions.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {allowedDecisions.map(d => (
                  <Badge key={d} variant="outline" className="rounded-none font-mono text-[10px] text-blue-400 border-blue-400/30 bg-blue-400/5">
                    {d}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {allowedSectors.length > 0 && (
            <div className="border-t border-border pt-3">
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Briefcase className="h-3 w-3" /> Allowed Sectors ({allowedSectors.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {allowedSectors.map(s => (
                  <Badge key={s} variant="outline" className="rounded-none font-mono text-[10px] text-violet-400 border-violet-400/30 bg-violet-400/5">
                    {s}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {allowedRegions.length > 0 && (
            <div className="border-t border-border pt-3">
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Globe className="h-3 w-3" /> Allowed Regions ({allowedRegions.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {allowedRegions.map(r => (
                  <Badge key={r} variant="outline" className="rounded-none font-mono text-[10px] text-cyan-400 border-cyan-400/30 bg-cyan-400/5">
                    {r}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {(allowedPaths.length > 0 || deniedPaths.length > 0) && (
            <div className="border-t border-border pt-3">
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2">Path Restrictions</div>
              {allowedPaths.length > 0 && (
                <div className="mb-2">
                  <span className="text-[10px] font-mono text-emerald-500 uppercase">Allowed: </span>
                  {allowedPaths.map(p => (
                    <code key={p} className="text-[10px] font-mono text-foreground bg-secondary px-1 mr-1">{p}</code>
                  ))}
                </div>
              )}
              {deniedPaths.length > 0 && (
                <div>
                  <span className="text-[10px] font-mono text-destructive uppercase">Denied: </span>
                  {deniedPaths.map(p => (
                    <code key={p} className="text-[10px] font-mono text-foreground bg-secondary px-1 mr-1">{p}</code>
                  ))}
                </div>
              )}
            </div>
          )}

          {platformPerms && (
            <div className="border-t border-border pt-3">
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Server className="h-3 w-3" /> Platform Permissions
              </div>
              <div className="grid grid-cols-2 gap-1">
                {(Object.entries(platformPerms) as [keyof PlatformPermissions, unknown][]).map(([key, val]) => (
                  <div key={key} className="flex justify-between font-mono text-xs">
                    <span className="text-muted-foreground">{String(key).replace(/_/g, ' ')}</span>
                    {typeof val === 'boolean' ? (
                      <Badge variant="outline" className={cn("rounded-none font-mono text-[9px]", val ? "text-emerald-500 border-emerald-500/30" : "text-destructive border-destructive/30")}>
                        {val ? 'YES' : 'NO'}
                      </Badge>
                    ) : Array.isArray(val) ? (
                      <span className="text-xs">{val.join(', ')}</span>
                    ) : (
                      <span>{String(val)}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="border-t border-border pt-3">
            <div className="text-xs font-mono text-muted-foreground uppercase mb-2">Budget Allocation</div>
            <div className="flex gap-4 font-mono text-xs">
              <div>
                <span className="text-muted-foreground">Total: </span>
                <span className="font-bold">${(mandate.budget.total_cents / 100).toFixed(2)}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Remaining: </span>
                <span className="font-bold text-emerald-500">${(mandate.budget.remaining_cents / 100).toFixed(2)}</span>
              </div>
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

export default function PoaMapPage() {
  const { data, isLoading } = useListMandates({ limit: 100 });
  const mandates = data?.items || [];

  const activeMandates = mandates.filter(m => m.status === "ACTIVE");
  const suspendedMandates = mandates.filter(m => m.status === "SUSPENDED");
  const draftMandates = mandates.filter(m => m.status === "DRAFT");
  const terminalMandates = mandates.filter(m => ["REVOKED", "EXPIRED", "DELETED", "SUPERSEDED", "BUDGET_EXCEEDED"].includes(m.status));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1" data-testid="text-page-title">PoA Permission Map</h1>
        <p className="text-muted-foreground font-mono text-sm">Flattened view of all mandate permissions: verbs, decisions, sectors, regions, and platform boundaries.</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <Card className="bg-card border-border rounded-none shadow-none border-t-2 border-t-emerald-500">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold font-mono text-emerald-500">{activeMandates.length}</div>
            <div className="text-xs font-mono text-muted-foreground uppercase">Active</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border rounded-none shadow-none border-t-2 border-t-amber-500">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold font-mono text-amber-500">{suspendedMandates.length}</div>
            <div className="text-xs font-mono text-muted-foreground uppercase">Suspended</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border rounded-none shadow-none border-t-2 border-t-blue-500">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold font-mono text-blue-500">{draftMandates.length}</div>
            <div className="text-xs font-mono text-muted-foreground uppercase">Draft</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border rounded-none shadow-none">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold font-mono text-muted-foreground">{terminalMandates.length}</div>
            <div className="text-xs font-mono text-muted-foreground uppercase">Terminal</div>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <div className="text-center text-primary font-mono uppercase tracking-widest animate-pulse py-12">Loading permission map...</div>
      ) : mandates.length === 0 ? (
        <Card className="bg-card border-border rounded-none shadow-none p-12 text-center">
          <Shield className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
          <div className="font-mono text-muted-foreground">No mandates found in system.</div>
        </Card>
      ) : (
        <div className="space-y-3">
          {activeMandates.length > 0 && (
            <div className="space-y-2">
              <h2 className="font-mono text-xs text-emerald-500 uppercase tracking-widest">Active Authorizations</h2>
              {activeMandates.map(m => <PermissionCard key={m.mandate_id} mandate={m} />)}
            </div>
          )}
          {suspendedMandates.length > 0 && (
            <div className="space-y-2 mt-6">
              <h2 className="font-mono text-xs text-amber-500 uppercase tracking-widest">Suspended Authorizations</h2>
              {suspendedMandates.map(m => <PermissionCard key={m.mandate_id} mandate={m} />)}
            </div>
          )}
          {draftMandates.length > 0 && (
            <div className="space-y-2 mt-6">
              <h2 className="font-mono text-xs text-blue-500 uppercase tracking-widest">Draft Authorizations</h2>
              {draftMandates.map(m => <PermissionCard key={m.mandate_id} mandate={m} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
