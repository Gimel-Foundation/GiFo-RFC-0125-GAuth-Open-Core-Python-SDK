import { useListMandates, useActivateMandate, useSuspendMandate, useResumeMandate, useRevokeMandate, getListMandatesQueryKey } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useState } from "react";
import { format } from "date-fns";
import { MandateStatus, GovernanceProfile } from "@workspace/api-client-react";
import { Play, Pause, ShieldOff, ChevronLeft, ChevronRight } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";

const STATUS_TABS = ["all", ...Object.values(MandateStatus)] as const;

export default function MandatesPage() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [profileFilter, setProfileFilter] = useState<string>("all");
  const [subjectFilter, setSubjectFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const queryClient = useQueryClient();

  const params = {
    limit: 20,
    cursor,
    status: statusFilter !== "all" ? statusFilter as typeof MandateStatus[keyof typeof MandateStatus] : undefined,
    governance_profile: profileFilter !== "all" ? profileFilter as typeof GovernanceProfile[keyof typeof GovernanceProfile] : undefined,
  };

  const { data, isLoading } = useListMandates(params);

  const activateMutation = useActivateMandate();
  const suspendMutation = useSuspendMandate();
  const resumeMutation = useResumeMandate();
  const revokeMutation = useRevokeMandate();

  const mandates = data?.items || [];

  const filteredMandates = mandates.filter(m =>
    subjectFilter ? m.parties.subject.toLowerCase().includes(subjectFilter.toLowerCase()) : true
  );

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

  const invalidateList = () => {
    queryClient.invalidateQueries({ queryKey: getListMandatesQueryKey(params) });
  };

  const handleActivate = async (id: string) => {
    await activateMutation.mutateAsync({ id });
    invalidateList();
  };
  const handleSuspend = async (id: string) => {
    await suspendMutation.mutateAsync({ id, data: { reason: "Suspended via dashboard" } });
    invalidateList();
  };
  const handleResume = async (id: string) => {
    await resumeMutation.mutateAsync({ id });
    invalidateList();
  };
  const handleRevoke = async (id: string) => {
    await revokeMutation.mutateAsync({ id, data: { reason: "Revoked via dashboard" } });
    invalidateList();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1" data-testid="text-page-title">Mandates</h1>
          <p className="text-muted-foreground font-mono text-sm">Active and historical Power of Attorney authorizations.</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-border pb-0">
        {STATUS_TABS.map((tab) => (
          <button
            key={tab}
            data-testid={`button-status-tab-${tab}`}
            onClick={() => { setStatusFilter(tab); setCursor(undefined); }}
            className={`px-3 py-2 text-xs font-mono uppercase transition-colors border-b-2 -mb-px ${
              statusFilter === tab
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      <Card className="bg-card border-border rounded-none shadow-none">
        <CardHeader className="border-b border-border pb-4 bg-secondary/30">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <Input
                placeholder="Filter by subject..."
                value={subjectFilter}
                onChange={(e) => setSubjectFilter(e.target.value)}
                className="font-mono rounded-none border-border bg-background focus-visible:ring-primary"
                data-testid="input-subject-filter"
              />
            </div>
            <div className="w-full sm:w-48">
              <Select value={profileFilter} onValueChange={(v) => { setProfileFilter(v); setCursor(undefined); }}>
                <SelectTrigger className="font-mono rounded-none border-border bg-background focus:ring-primary" data-testid="select-profile-filter">
                  <SelectValue placeholder="All Profiles" />
                </SelectTrigger>
                <SelectContent className="rounded-none border-border">
                  <SelectItem value="all">All Profiles</SelectItem>
                  {Object.values(GovernanceProfile).map((profile) => (
                    <SelectItem key={profile} value={profile}>{profile}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left font-mono">
              <thead className="text-xs text-muted-foreground uppercase bg-secondary/10 border-b border-border">
                <tr>
                  <th className="px-4 py-3 font-medium">ID / Subject</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Profile</th>
                  <th className="px-4 py-3 font-medium">Budget</th>
                  <th className="px-4 py-3 font-medium">Updated</th>
                  <th className="px-4 py-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {isLoading ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">Loading mandates...</td>
                  </tr>
                ) : filteredMandates.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">No mandates found matching filters.</td>
                  </tr>
                ) : (
                  filteredMandates.map((mandate) => {
                    const budgetPct = mandate.budget.total_cents > 0
                      ? Math.round((mandate.budget.consumed_cents / mandate.budget.total_cents) * 100)
                      : 0;
                    return (
                      <tr key={mandate.mandate_id} className="hover:bg-secondary/30 transition-colors" data-testid={`row-mandate-${mandate.mandate_id}`}>
                        <td className="px-4 py-3">
                          <Link href={`/mandates/${mandate.mandate_id}`} className="font-bold text-primary hover:underline" data-testid={`link-mandate-${mandate.mandate_id}`}>
                            {mandate.mandate_id.split('-')[0]}...
                          </Link>
                          <div className="text-xs text-muted-foreground">{mandate.parties.subject}</div>
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant="outline" className={`rounded-none font-mono text-[10px] ${getStatusColor(mandate.status)}`}>
                            {mandate.status}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-xs uppercase">{mandate.governance_profile}</td>
                        <td className="px-4 py-3">
                          <div className="text-xs">${(mandate.budget.consumed_cents / 100).toFixed(0)} / ${(mandate.budget.total_cents / 100).toFixed(0)}</div>
                          <div className="w-16 h-1.5 bg-secondary mt-1 rounded-none">
                            <div
                              className={`h-full rounded-none ${budgetPct > 95 ? 'bg-destructive' : budgetPct > 80 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                              style={{ width: `${Math.min(budgetPct, 100)}%` }}
                            />
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">
                          {format(new Date(mandate.updated_at), 'yyyy-MM-dd HH:mm')}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-1">
                            {mandate.status === "DRAFT" && (
                              <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-emerald-500 hover:bg-emerald-500/10" onClick={() => handleActivate(mandate.mandate_id)} disabled={activateMutation.isPending} title="Activate" data-testid={`button-activate-${mandate.mandate_id}`}>
                                <Play className="h-3.5 w-3.5" />
                              </Button>
                            )}
                            {mandate.status === "ACTIVE" && (
                              <>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-amber-500 hover:bg-amber-500/10" onClick={() => handleSuspend(mandate.mandate_id)} disabled={suspendMutation.isPending} title="Suspend" data-testid={`button-suspend-${mandate.mandate_id}`}>
                                  <Pause className="h-3.5 w-3.5" />
                                </Button>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-destructive hover:bg-destructive/10" onClick={() => handleRevoke(mandate.mandate_id)} disabled={revokeMutation.isPending} title="Revoke" data-testid={`button-revoke-${mandate.mandate_id}`}>
                                  <ShieldOff className="h-3.5 w-3.5" />
                                </Button>
                              </>
                            )}
                            {mandate.status === "SUSPENDED" && (
                              <>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-emerald-500 hover:bg-emerald-500/10" onClick={() => handleResume(mandate.mandate_id)} disabled={resumeMutation.isPending} title="Resume" data-testid={`button-resume-${mandate.mandate_id}`}>
                                  <Play className="h-3.5 w-3.5" />
                                </Button>
                                <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-destructive hover:bg-destructive/10" onClick={() => handleRevoke(mandate.mandate_id)} disabled={revokeMutation.isPending} title="Revoke" data-testid={`button-revoke-${mandate.mandate_id}`}>
                                  <ShieldOff className="h-3.5 w-3.5" />
                                </Button>
                              </>
                            )}
                            <Link href={`/mandates/${mandate.mandate_id}`}>
                              <Button variant="outline" size="sm" className="rounded-none font-mono text-xs h-7 hover:bg-primary hover:text-primary-foreground border-primary/30" data-testid={`button-details-${mandate.mandate_id}`}>
                                Details
                              </Button>
                            </Link>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between px-4 py-3 border-t border-border bg-secondary/10">
            <div className="text-xs font-mono text-muted-foreground">
              {filteredMandates.length} result{filteredMandates.length !== 1 ? 's' : ''}
              {data?.next_cursor ? ' (more available)' : ''}
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                className="rounded-none font-mono text-xs h-7"
                disabled={!cursor}
                onClick={() => setCursor(undefined)}
                data-testid="button-prev-page"
              >
                <ChevronLeft className="h-3 w-3 mr-1" /> First
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="rounded-none font-mono text-xs h-7"
                disabled={!data?.next_cursor}
                onClick={() => setCursor(data?.next_cursor ?? undefined)}
                data-testid="button-next-page"
              >
                Next <ChevronRight className="h-3 w-3 ml-1" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
