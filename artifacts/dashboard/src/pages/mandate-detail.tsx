import { useGetMandate, useGetMandateHistory, useGetDelegationChain, useActivateMandate, useSuspendMandate, useResumeMandate, useRevokeMandate } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Clock, Play, Pause, ShieldOff, ShieldAlert, Activity, Link as LinkIcon, Database, ArrowLeft, ChevronDown, ChevronRight, Plus, Zap, Ban, RotateCcw, CheckCircle2, AlertTriangle } from "lucide-react";
import { Link, useParams } from "wouter";
import { format } from "date-fns";
import { useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import { getGetMandateQueryKey, getGetMandateHistoryQueryKey } from "@workspace/api-client-react";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";
import { useState } from "react";

function DelegationNode({ entry, chain, currentId, depth }: { entry: { mandate_id: string; delegation_depth: number; delegate_agent_id: string; parent_mandate_id: string | null }; chain: typeof entry[]; currentId: string; depth: number }) {
  const [expanded, setExpanded] = useState(true);
  const children = chain.filter(c => c.parent_mandate_id === entry.mandate_id);
  const isCurrent = entry.mandate_id === currentId;

  return (
    <div className="font-mono text-xs" style={{ paddingLeft: depth > 0 ? 20 : 0 }}>
      <div
        className={cn(
          "flex items-center gap-2 py-2 px-2 transition-colors rounded-none",
          isCurrent ? "bg-primary/10 border-l-2 border-primary" : "hover:bg-secondary/30 border-l-2 border-border"
        )}
      >
        {children.length > 0 ? (
          <button onClick={() => setExpanded(!expanded)} className="text-muted-foreground">
            {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          </button>
        ) : (
          <div className="w-3" />
        )}
        <div className="h-2 w-2 rounded-full bg-primary ring-2 ring-background" />
        <div className="flex-1">
          <div className="font-bold text-primary">
            {isCurrent ? (
              <span data-testid="text-current-mandate">Current</span>
            ) : (
              <Link href={`/mandates/${entry.mandate_id}`} className="hover:underline" data-testid={`link-chain-${entry.mandate_id}`}>
                {entry.mandate_id.split('-')[0]}...
              </Link>
            )}
          </div>
          <div className="text-muted-foreground">Depth: {entry.delegation_depth} | Agent: {entry.delegate_agent_id}</div>
        </div>
      </div>
      {expanded && children.map(child => (
        <DelegationNode key={child.mandate_id} entry={child} chain={chain} currentId={currentId} depth={depth + 1} />
      ))}
    </div>
  );
}

export default function MandateDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();

  const { data: mandate, isLoading: isMandateLoading } = useGetMandate(id);
  const { data: history, isLoading: isHistoryLoading } = useGetMandateHistory(id);
  const { data: delegationChain, isLoading: isDelegationLoading } = useGetDelegationChain(id);
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

  const budgetConsumed = budget?.consumed_cents ?? 0;
  const budgetTotal = budget?.total_cents ?? 0;
  const budgetRemaining = budget?.remaining_cents ?? 0;
  const budgetReserved = budget?.reserved_for_delegations_cents ?? 0;
  const budgetUtil = budgetTotal > 0 ? (budgetConsumed / budgetTotal) * 100 : 0;
  const isBudgetWarning = budgetUtil > 80;
  const isBudgetCritical = budgetUtil > 95;

  const donutData = [
    { name: "Consumed", value: budgetConsumed, color: isBudgetCritical ? "#ef4444" : isBudgetWarning ? "#f59e0b" : "#10b981" },
    { name: "Reserved", value: budgetReserved, color: "#6366f1" },
    { name: "Available", value: Math.max(0, budgetRemaining - budgetReserved), color: "#334155" },
  ].filter(d => d.value > 0);

  const barData = budget ? [
    { name: "Total", cents: budgetTotal },
    { name: "Consumed", cents: budgetConsumed },
    { name: "Reserved", cents: budgetReserved },
    { name: "Available", cents: Math.max(0, budgetRemaining - budgetReserved) },
  ] : [];

  const rootEntries = delegationChain?.chain?.filter((e: { parent_mandate_id: string | null }) => e.parent_mandate_id === null) || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4 text-muted-foreground font-mono text-sm mb-4">
        <Link href="/mandates" className="hover:text-primary flex items-center gap-1 transition-colors" data-testid="link-back">
          <ArrowLeft className="h-4 w-4" /> Back to List
        </Link>
      </div>

      <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-3xl font-bold tracking-tight font-mono text-primary break-all" data-testid="text-mandate-id">{mandate.mandate_id}</h1>
            <Badge variant="outline" className={cn("rounded-none font-mono text-xs uppercase px-2 py-1", getStatusColor(mandate.status))} data-testid="badge-mandate-status">
              {mandate.status}
            </Badge>
          </div>
          <p className="text-muted-foreground font-mono text-sm uppercase">Subject: {mandate.parties.subject}</p>
        </div>

        <div className="flex flex-wrap gap-2" data-testid="actions-container">
          {mandate.status === "DRAFT" && (
            <Button onClick={() => handleAction('activate')} disabled={activateMutation.isPending} className="rounded-none font-mono uppercase bg-emerald-500 hover:bg-emerald-600 text-black" data-testid="button-activate">
              <Play className="h-4 w-4 mr-2" /> Activate
            </Button>
          )}
          {mandate.status === "ACTIVE" && (
            <>
              <Button onClick={() => handleAction('suspend')} disabled={suspendMutation.isPending} variant="outline" className="rounded-none font-mono uppercase border-amber-500/50 text-amber-500 hover:bg-amber-500/10" data-testid="button-suspend">
                <Pause className="h-4 w-4 mr-2" /> Suspend
              </Button>
              <Button onClick={() => handleAction('revoke')} disabled={revokeMutation.isPending} variant="destructive" className="rounded-none font-mono uppercase" data-testid="button-revoke">
                <ShieldOff className="h-4 w-4 mr-2" /> Revoke
              </Button>
            </>
          )}
          {mandate.status === "SUSPENDED" && (
            <>
              <Button onClick={() => handleAction('resume')} disabled={resumeMutation.isPending} className="rounded-none font-mono uppercase bg-emerald-500 hover:bg-emerald-600 text-black" data-testid="button-resume">
                <Play className="h-4 w-4 mr-2" /> Resume
              </Button>
              <Button onClick={() => handleAction('revoke')} disabled={revokeMutation.isPending} variant="destructive" className="rounded-none font-mono uppercase" data-testid="button-revoke">
                <ShieldOff className="h-4 w-4 mr-2" /> Revoke
              </Button>
            </>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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
                <div className="text-2xl text-primary font-bold" data-testid="text-ttl-remaining">{Math.floor(mandate.remaining_ttl_seconds / 3600)}h {Math.floor((mandate.remaining_ttl_seconds % 3600) / 60)}m</div>
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
                    <span className={isBudgetCritical ? "text-destructive font-bold" : isBudgetWarning ? "text-amber-500 font-bold" : "text-emerald-500"} data-testid="text-budget-consumed">
                      ${(budgetConsumed / 100).toFixed(2)} / ${(budgetTotal / 100).toFixed(2)} ({budgetUtil.toFixed(1)}%)
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="h-48" data-testid="chart-budget-donut">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={donutData}
                            cx="50%"
                            cy="50%"
                            innerRadius={50}
                            outerRadius={75}
                            paddingAngle={2}
                            dataKey="value"
                          >
                            {donutData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                            ))}
                          </Pie>
                          <Tooltip
                            formatter={(value: number) => `$${(value / 100).toFixed(2)}`}
                            contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 0, fontFamily: 'monospace', fontSize: 11 }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>

                    <div className="h-48" data-testid="chart-budget-bar">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={barData} layout="vertical">
                          <XAxis type="number" tickFormatter={(v: number) => `$${(v / 100).toFixed(0)}`} tick={{ fontFamily: 'monospace', fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                          <YAxis type="category" dataKey="name" width={70} tick={{ fontFamily: 'monospace', fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                          <Tooltip formatter={(value: number) => `$${(value / 100).toFixed(2)}`} contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 0, fontFamily: 'monospace', fontSize: 11 }} />
                          <Bar dataKey="cents" fill="hsl(var(--primary))" radius={0} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div className="grid grid-cols-4 gap-4 pt-4 border-t border-border">
                    <div>
                      <div className="text-xs text-muted-foreground font-mono uppercase mb-1">Total</div>
                      <div className="font-mono font-bold">${(budgetTotal / 100).toFixed(2)}</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground font-mono uppercase mb-1">Consumed</div>
                      <div className="font-mono font-bold">${(budgetConsumed / 100).toFixed(2)}</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground font-mono uppercase mb-1">Reserved</div>
                      <div className="font-mono font-bold">${(budgetReserved / 100).toFixed(2)}</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground font-mono uppercase mb-1">Available</div>
                      <div className="font-mono font-bold text-emerald-500">${(Math.max(0, budgetRemaining - budgetReserved) / 100).toFixed(2)}</div>
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
                      <td className="px-4 py-3 text-muted-foreground uppercase">{key.replace(/_/g, ' ')}</td>
                      <td className="px-4 py-3 text-right">
                        {typeof val === 'boolean' ? (
                          <Badge variant="outline" className={cn("rounded-none font-mono text-[10px] uppercase", val ? 'text-emerald-500 border-emerald-500/30' : 'text-muted-foreground border-border')}>
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

        <div className="space-y-6">
          <Card className="bg-card border-border rounded-none shadow-none flex flex-col h-[400px]">
            <CardHeader className="border-b border-border bg-secondary/20 py-3">
              <CardTitle className="font-mono uppercase text-sm flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4" /> Audit Trail
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 overflow-y-auto flex-1">
              {isHistoryLoading ? (
                <div className="p-4 text-center text-muted-foreground font-mono text-xs">Loading logs...</div>
              ) : !history || history.length === 0 ? (
                <div className="p-4 text-center text-muted-foreground font-mono text-xs">No audit logs found.</div>
              ) : (
                <div className="relative">
                  <div className="absolute left-[11px] top-2 bottom-2 w-px bg-border" />
                  <div className="space-y-4">
                    {history.map((log) => {
                      const opIcon = (() => {
                        const op = log.operation_type.toLowerCase();
                        if (op.includes('create')) return <Plus className="h-3 w-3" />;
                        if (op.includes('activate')) return <CheckCircle2 className="h-3 w-3" />;
                        if (op.includes('suspend')) return <Pause className="h-3 w-3" />;
                        if (op.includes('resume')) return <Play className="h-3 w-3" />;
                        if (op.includes('revoke')) return <Ban className="h-3 w-3" />;
                        if (op.includes('budget')) return <AlertTriangle className="h-3 w-3" />;
                        if (op.includes('delegate')) return <Zap className="h-3 w-3" />;
                        return <RotateCcw className="h-3 w-3" />;
                      })();

                      const opColor = (() => {
                        const op = log.operation_type.toLowerCase();
                        if (op.includes('create')) return 'bg-blue-500 text-white';
                        if (op.includes('activate') || op.includes('resume')) return 'bg-emerald-500 text-white';
                        if (op.includes('suspend')) return 'bg-amber-500 text-black';
                        if (op.includes('revoke') || op.includes('budget_exceeded')) return 'bg-destructive text-white';
                        return 'bg-primary text-primary-foreground';
                      })();

                      return (
                        <div key={log.log_id} className="relative flex gap-3 items-start" data-testid={`audit-entry-${log.log_id}`}>
                          <div className={cn("relative z-10 flex-shrink-0 h-6 w-6 rounded-full flex items-center justify-center", opColor)}>
                            {opIcon}
                          </div>
                          <div className="flex-1 min-w-0 pb-1">
                            <div className="flex items-baseline justify-between gap-2">
                              <span className="font-mono text-xs font-bold uppercase text-foreground">{log.operation_type}</span>
                              <span className="font-mono text-[10px] text-muted-foreground whitespace-nowrap">{format(new Date(log.created_at), 'MM-dd HH:mm')}</span>
                            </div>
                            <div className="font-mono text-[10px] text-muted-foreground truncate mt-0.5" title={log.caller_identity}>
                              {log.caller_identity}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
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
            <CardContent className="p-4" data-testid="delegation-chain">
              {isDelegationLoading ? (
                <div className="text-center text-muted-foreground font-mono text-xs">Tracing chain...</div>
              ) : !delegationChain || delegationChain.chain.length <= 1 ? (
                <div className="text-center text-muted-foreground font-mono text-xs">Root mandate. No delegation ancestors.</div>
              ) : (
                <div className="space-y-1">
                  {rootEntries.map((entry: { mandate_id: string; delegation_depth: number; delegate_agent_id: string; parent_mandate_id: string | null }) => (
                    <DelegationNode key={entry.mandate_id} entry={entry} chain={delegationChain.chain} currentId={id} depth={0} />
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
