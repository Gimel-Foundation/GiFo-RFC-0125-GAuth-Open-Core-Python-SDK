import { useListProfiles, getGetProfileCeilingsQueryKey, getProfileCeilings } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Database, AlertCircle } from "lucide-react";
import type { GovernanceProfile, ProfileCeilings } from "@workspace/api-client-react";
import { useQueries } from "@tanstack/react-query";

const PROFILES: GovernanceProfile[] = ["minimal" as GovernanceProfile, "standard" as GovernanceProfile, "strict" as GovernanceProfile, "enterprise" as GovernanceProfile, "behoerde" as GovernanceProfile];

const CEILING_ROWS: { key: keyof ProfileCeilings; label: string; type: 'boolean' | 'number' | 'string' }[] = [
  { key: 'min_approval_mode', label: 'Min Approval Mode', type: 'string' },
  { key: 'agent_delegation', label: 'Agent Delegation', type: 'boolean' },
  { key: 'max_delegation_depth', label: 'Max Delegation Depth', type: 'number' },
  { key: 'max_session_duration_minutes', label: 'Max Session Duration', type: 'number' },
  { key: 'max_tool_calls', label: 'Max Tool Calls', type: 'number' },
  { key: 'shell_mode', label: 'Shell Mode', type: 'string' },
  { key: 'db_production', label: 'DB Production Access', type: 'boolean' },
  { key: 'db_write', label: 'DB Write Access', type: 'boolean' },
  { key: 'secrets_read', label: 'Secrets Read', type: 'boolean' },
];

function CellValue({ value, type }: { value: unknown; type: 'boolean' | 'number' | 'string' }) {
  if (value === null || value === undefined) {
    return <span className="text-muted-foreground/40">&mdash;</span>;
  }

  if (type === 'boolean') {
    return (
      <Badge
        variant="outline"
        className={`rounded-none font-mono text-[9px] uppercase ${value ? 'text-emerald-500 border-emerald-500/30 bg-emerald-500/5' : 'text-destructive border-destructive/30 bg-destructive/5'}`}
      >
        {value ? 'YES' : 'NO'}
      </Badge>
    );
  }

  if (type === 'number') {
    return <span className="font-bold">{value === 0 ? 'UNLIMITED' : String(value)}</span>;
  }

  return <span className="font-bold uppercase">{String(value)}</span>;
}

export default function ProfilesPage() {
  const { data: profiles, isLoading: isProfilesLoading, isError: isProfilesError } = useListProfiles();

  const ceilingsQueries = useQueries({
    queries: PROFILES.map(p => ({
      queryKey: getGetProfileCeilingsQueryKey(p),
      queryFn: ({ signal }: { signal: AbortSignal }) => getProfileCeilings(p, { signal }),
      retry: 1,
    })),
  });

  const allLoading = isProfilesLoading || ceilingsQueries.some(q => q.isLoading);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1" data-testid="text-page-title">Governance Profiles</h1>
        <p className="text-muted-foreground font-mono text-sm">Side-by-side comparison of all operational profiles and their absolute ceilings.</p>
      </div>

      {isProfilesError ? (
        <Card className="bg-card border-border rounded-none shadow-none p-12 text-center">
          <AlertCircle className="h-12 w-12 text-destructive mx-auto mb-4" />
          <div className="font-mono text-destructive mb-2">Failed to load profiles</div>
          <div className="font-mono text-xs text-muted-foreground">Check API connectivity and authentication.</div>
        </Card>
      ) : allLoading ? (
        <div className="p-8 text-center text-primary font-mono animate-pulse uppercase">Loading profiles...</div>
      ) : (
        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border bg-secondary/10">
            <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
              <Shield className="h-4 w-4" /> Profile Ceiling Comparison
            </CardTitle>
            <CardDescription className="font-mono text-xs">
              Absolute limits per governance profile. Mandates cannot exceed the ceiling of their assigned profile.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left font-mono" data-testid="table-profile-comparison">
                <thead className="text-xs text-muted-foreground uppercase bg-secondary/20 border-b border-border">
                  <tr>
                    <th className="px-4 py-3 font-medium sticky left-0 bg-secondary/20 z-10 min-w-[180px]">Property</th>
                    {PROFILES.map(p => (
                      <th key={p} className="px-4 py-3 font-medium text-center min-w-[130px]">
                        <span className="text-primary">{p}</span>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {CEILING_ROWS.map((row) => (
                    <tr key={row.key} className="hover:bg-secondary/20">
                      <td className="px-4 py-3 text-muted-foreground uppercase sticky left-0 bg-card z-10 border-r border-border/50">
                        {row.key === 'shell_mode' || row.key === 'db_production' || row.key === 'db_write' || row.key === 'secrets_read' ? (
                          <span className="flex items-center gap-1"><Database className="h-3 w-3 inline" /> {row.label}</span>
                        ) : row.label}
                      </td>
                      {ceilingsQueries.map((q, idx) => {
                        const ceiling = q.data as ProfileCeilings | null | undefined;
                        return (
                          <td key={PROFILES[idx]} className="px-4 py-3 text-center" data-testid={`cell-${row.key}-${PROFILES[idx]}`}>
                            {ceiling ? (
                              <CellValue value={ceiling[row.key]} type={row.type} />
                            ) : (
                              <span className="text-muted-foreground/40">&mdash;</span>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}

                  <tr className="bg-secondary/5">
                    <td colSpan={PROFILES.length + 1} className="px-4 py-2 text-xs uppercase text-muted-foreground font-bold tracking-widest">Description</td>
                  </tr>
                  <tr className="hover:bg-secondary/20">
                    <td className="px-4 py-3 text-muted-foreground uppercase sticky left-0 bg-card z-10 border-r border-border/50">Info</td>
                    {PROFILES.map(p => {
                      const profile = profiles?.find(pr => pr.name === p);
                      return (
                        <td key={p} className="px-4 py-3 text-center text-xs text-muted-foreground max-w-[150px]">
                          {profile?.description || '\u2014'}
                        </td>
                      );
                    })}
                  </tr>
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
