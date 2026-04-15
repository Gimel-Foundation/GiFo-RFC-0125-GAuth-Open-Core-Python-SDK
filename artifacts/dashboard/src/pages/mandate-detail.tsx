import { useGetMandate, useGetMandateHistory, useGetDelegationChain, useActivateMandate, useSuspendMandate, useResumeMandate, useRevokeMandate } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Clock, Play, Pause, ShieldOff, ShieldAlert, Activity, Link as LinkIcon, Database, ArrowLeft } from "lucide-react";
import { Link, useParams } from "wouter";
import { format } from "date-fns";
import { Progress } from "@/components/ui/progress";
import { useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import { getGetMandateQueryKey, getGetMandateHistoryQueryKey } from "@workspace/api-client-react";

export default function MandateDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();

  const { data: mandate, isLoading: isMandateLoading } = useGetMandate(id);
  const { data: history, isLoading: isHistoryLoading } = useGetMandateHistory(id);
  const { data: delegationChain, isLoading: isDelegationLoading } = useGetDelegationChain(id);
  // Using budget from mandate detail directly for now since useGetBudget might be custom implementation or alias not fully known without looking at api.ts closely. mandate detail provides budget.
  const budget = mandate?.budget;

  const activateMutation = useActivateMandate();
  const suspendMutation = useSuspendMandate();
  const resumeMutation = useResumeMandate();
  const revokeMutation = useRevokeMandate();

  if (isMandateLoading) {
    return <div className="p-8 text-center text-primary font-mono uppercase tracking-widest animate-pulse">Loading Mandate Telemetry...</div>;
  }

  if (!mandate) {
    return <div className="p-8 text-center text-destructive font-mono uppercase tracking-widest">Mandate Not Found</div>;
  }

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

  const handleAction = async (action: 'activate' | 'suspend' | 'resume' | 'revoke') => {
    try {
      if (action === 'activate') await activateMutation.mutateAsync({ id });
      if (action === 'suspend') await suspendMutation.mutateAsync({ id, data: { reason: "Admin suspended via dashboard" } });
      if (action === 'resume') await resumeMutation.mutateAsync({ id });
      if (action === 'revoke') await revokeMutation.mutateAsync({ id, data: { reason: "Admin revoked via dashboard" } });

      queryClient.invalidateQueries({ queryKey: getGetMandateQueryKey(id) });
      queryClient.invalidateQueries({ queryKey: getGetMandateHistoryQueryKey(id) });
    } catch (e) {
      console.error(e);
    }
  };

  const budgetUtil = budget ? (budget.consumed_cents / budget.total_cents) * 100 : 0;
  const isBudgetWarning = budgetUtil > 80;
  const isBudgetCritical = budgetUtil > 95;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4 text-muted-foreground font-mono text-sm mb-4">
        <Link href="/mandates" className="hover:text-primary flex items-center gap-1 transition-colors">
          <ArrowLeft className="h-4 w-4" /> Back to List
        </Link>
      </div>

      <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-3xl font-bold tracking-tight font-mono text-primary break-all">{mandate.mandate_id}</h1>
            <Badge variant="outline" className={`rounded-none font-mono text-xs uppercase px-2 py-1 ${getStatusColor(mandate.status)}`}>
              {mandate.status}
            </Badge>
          </div>
          <p className="text-muted-foreground font-mono text-sm uppercase">Subject: {mandate.parties.subject}</p>
        </div>

        <div className="flex flex-wrap gap-2">
          {mandate.status === "DRAFT" && (
            <Button onClick={() => handleAction('activate')} disabled={activateMutation.isPending} className="rounded-none font-mono uppercase bg-emerald-500 hover:bg-emerald-600 text-black">
              <Play className="h-4 w-4 mr-2" /> Activate
            </Button>
          )}
          {mandate.status === "ACTIVE" && (
            <>
              <Button onClick={() => handleAction('suspend')} disabled={suspendMutation.isPending} variant="outline" className="rounded-none font-mono uppercase border-amber-500/50 text-amber-500 hover:bg-amber-500/10">
                <Pause className="h-4 w-4 mr-2" /> Suspend
              </Button>
              <Button onClick={() => handleAction('revoke')} disabled={revokeMutation.isPending} variant="destructive" className="rounded-none font-mono uppercase">
                <ShieldOff className="h-4 w-4 mr-2" /> Revoke
              </Button>
            </>
          )}
          {mandate.status === "SUSPENDED" && (
            <>
              <Button onClick={() => handleAction('resume')} disabled={resumeMutation.isPending} className="rounded-none font-mono uppercase bg-emerald-500 hover:bg-emerald-600 text-black">
                <Play className="h-4 w-4 mr-2" /> Resume
              </Button>
              <Button onClick={() => handleAction('revoke')} disabled={revokeMutation.isPending} variant="destructive" className="rounded-none font-mono uppercase">
                <ShieldOff className="h-4 w-4 mr-2" /> Revoke
              </Button>
            </>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Details */}
        <div className="lg:col-span-2 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-card border-border rounded-none shadow-none">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase flex items-center gap-2">
                  <Database className="h-4 w-4" /> Scope Details
                </CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm space-y-2">
                <div className="flex justify-between border-b border-border/50 pb-1">
                  <span className="text-muted-foreground">Profile</span>
                  <span className="uppercase text-primary">{mandate.governance_profile}</span>
                </div>
                <div className="flex justify-between border-b border-border/50 pb-1">
                  <span className="text-muted-foreground">Phase</span>
                  <span className="uppercase">{mandate.phase}</span>
                </div>
                <div className="flex justify-between border-b border-border/50 pb-1">
                  <span className="text-muted-foreground">Appr. Mode</span>
                  <span className="uppercase">{mandate.requirements.approval_mode}</span>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card border-border rounded-none shadow-none">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase flex items-center gap-2">
                  <Clock className="h-4 w-4" /> Time To Live
                </CardTitle>
              </CardHeader>
              <CardContent className="font-mono">
                <div className="text-2xl text-primary font-bold">{Math.floor(mandate.remaining_ttl_seconds / 3600)}h {Math.floor((mandate.remaining_ttl_seconds % 3600) / 60)}m</div>
                <div className="text-xs text-muted-foreground mt-1">Remaining of {mandate.ttl_seconds}s total</div>
                <div className="text-xs text-muted-foreground mt-3 flex justify-between">
                  <span>Created:</span> <span>{format(new Date(mandate.created_at), 'yyyy-MM-dd')}</span>
                </div>
                <div className="text-xs text-muted-foreground flex justify-between">
                  <span>Expires:</span> <span>{mandate.expires_at ? format(new Date(mandate.expires_at), 'yyyy-MM-dd HH:mm') : 'N/A'}</span>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card className="bg-card border-border rounded-none shadow-none">
            <CardHeader className="border-b border-border bg-secondary/20">
              <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
                <Activity className="h-4 w-4" /> Budget Utilization
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-6">
              {budget ? (
                <div className="space-y-4">
                  <div className="flex justify-between font-mono text-sm uppercase">
                    <span className="text-muted-foreground">Consumed</span>
                    <span className={isBudgetCritical ? "text-destructive font-bold" : isBudgetWarning ? "text-amber-500 font-bold" : "text-emerald-500"}>
                      ${(budget.consumed_cents / 100).toFixed(2)} / ${(budget.total_cents / 100).toFixed(2)}
                    </span>
                  </div>
                  <Progress 
                    value={budgetUtil} 
                    className={cn("h-3 rounded-none bg-secondary [&>div]:transition-all", isBudgetCritical ? "[&>div]:bg-destructive" : isBudgetWarning ? "[&>div]:bg-amber-500" : "[&>div]:bg-emerald-500")}
                  />
                  <div className="grid grid-cols-3 gap-4 pt-4 border-t border-border">
                    <div>
                      <div className="text-xs text-muted-foreground font-mono uppercase mb-1">Total</div>
                      <div className="font-mono">${(budget.total_cents / 100).toFixed(2)}</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground font-mono uppercase mb-1">Remaining</div>
                      <div className="font-mono">${(budget.remaining_cents / 100).toFixed(2)}</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground font-mono uppercase mb-1">Reserved</div>
                      <div className="font-mono">${(budget.reserved_for_delegations_cents / 100).toFixed(2)}</div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center text-muted-foreground font-mono text-sm py-4">Budget data unavailable</div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-card border-border rounded-none shadow-none">
            <CardHeader className="border-b border-border bg-secondary/20">
              <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" /> Platform Permissions
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-sm text-left font-mono">
                <tbody className="divide-y divide-border">
                  {Object.entries(mandate.scope.platform_permissions || {}).map(([key, val]) => (
                    <tr key={key} className="hover:bg-secondary/30">
                      <td className="px-4 py-3 text-muted-foreground uppercase">{key.replace('_', ' ')}</td>
                      <td className="px-4 py-3 text-right">
                        {typeof val === 'boolean' ? (
                          <Badge variant="outline" className={`rounded-none font-mono text-[10px] uppercase ${val ? 'text-emerald-500 border-emerald-500/30' : 'text-muted-foreground border-border'}`}>
                            {val ? 'YES' : 'NO'}
                          </Badge>
                        ) : (
                          <span className="uppercase">{String(val)}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {Object.keys(mandate.scope.platform_permissions || {}).length === 0 && (
                    <tr><td colSpan={2} className="px-4 py-6 text-center text-muted-foreground">No specific platform permissions defined.</td></tr>
                  )}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </div>

        {/* Right Column - Logs & Chains */}
        <div className="space-y-6">
          <Card className="bg-card border-border rounded-none shadow-none flex flex-col h-[400px]">
            <CardHeader className="border-b border-border bg-secondary/20 py-3">
              <CardTitle className="font-mono uppercase text-sm flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4" /> Audit Trail
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0 overflow-y-auto flex-1">
              {isHistoryLoading ? (
                <div className="p-4 text-center text-muted-foreground font-mono text-xs">Loading logs...</div>
              ) : !history || history.length === 0 ? (
                <div className="p-4 text-center text-muted-foreground font-mono text-xs">No audit logs found.</div>
              ) : (
                <div className="divide-y divide-border">
                  {history.map((log) => (
                    <div key={log.log_id} className="p-3 text-xs font-mono space-y-1 hover:bg-secondary/30">
                      <div className="flex justify-between items-start">
                        <span className="text-primary font-bold uppercase">{log.operation_type}</span>
                        <span className="text-muted-foreground">{format(new Date(log.created_at), 'MM-dd HH:mm')}</span>
                      </div>
                      <div className="text-muted-foreground truncate" title={log.caller_identity}>
                        Actor: {log.caller_identity}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-card border-border rounded-none shadow-none">
            <CardHeader className="border-b border-border bg-secondary/20 py-3">
              <CardTitle className="font-mono uppercase text-sm flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <LinkIcon className="h-4 w-4" /> Delegation Chain
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              {isDelegationLoading ? (
                <div className="text-center text-muted-foreground font-mono text-xs">Tracing chain...</div>
              ) : !delegationChain || delegationChain.chain.length <= 1 ? (
                <div className="text-center text-muted-foreground font-mono text-xs">Root mandate. No delegation ancestors.</div>
              ) : (
                <div className="space-y-4">
                  {delegationChain.chain.map((entry, idx) => (
                    <div key={entry.mandate_id} className="relative pl-6 font-mono text-xs">
                      {idx !== delegationChain.chain.length - 1 && (
                        <div className="absolute left-2 top-4 bottom-[-16px] w-px bg-border"></div>
                      )}
                      <div className="absolute left-1 top-1.5 h-2 w-2 rounded-full bg-primary ring-4 ring-background"></div>
                      <div className="font-bold text-primary mb-1">
                        {entry.mandate_id === id ? 'Current' : <Link href={`/mandates/${entry.mandate_id}`} className="hover:underline">{entry.mandate_id.split('-')[0]}...</Link>}
                      </div>
                      <div className="text-muted-foreground">Depth: {entry.delegation_depth}</div>
                      <div className="text-muted-foreground truncate" title={entry.delegate_agent_id}>Agent: {entry.delegate_agent_id}</div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}