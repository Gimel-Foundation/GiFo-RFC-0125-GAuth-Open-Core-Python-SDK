import { useListProfiles, useGetProfileCeilings, getGetProfileCeilingsQueryKey } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Users, Shield, Database, ChevronRight } from "lucide-react";
import type { GovernanceProfile } from "@workspace/api-client-react";
import { useState } from "react";

export default function ProfilesPage() {
  const { data: profiles, isLoading: isProfilesLoading } = useListProfiles();
  const [selectedProfile, setSelectedProfile] = useState<GovernanceProfile | null>(null);

  const { data: ceilings, isLoading: isCeilingsLoading } = useGetProfileCeilings(
    selectedProfile as GovernanceProfile, 
    { query: { enabled: !!selectedProfile, queryKey: getGetProfileCeilingsQueryKey(selectedProfile as GovernanceProfile) } }
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1">Governance Profiles</h1>
        <p className="text-muted-foreground font-mono text-sm">Defined operational envelopes and their absolute maximums (ceilings).</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-1 space-y-4">
          <Card className="bg-card border-border rounded-none shadow-none">
            <CardHeader className="border-b border-border pb-3 bg-secondary/20">
              <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
                <Users className="h-4 w-4" /> Available Profiles
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {isProfilesLoading ? (
                <div className="p-6 text-center text-muted-foreground font-mono text-sm">Loading profiles...</div>
              ) : (
                <div className="divide-y divide-border">
                  {profiles?.map((profile) => (
                    <div 
                      key={profile.name} 
                      onClick={() => setSelectedProfile(profile.name as GovernanceProfile)}
                      className={`p-4 cursor-pointer transition-colors flex items-center justify-between ${selectedProfile === profile.name ? 'bg-primary/10 border-l-4 border-l-primary' : 'hover:bg-secondary/30 border-l-4 border-l-transparent'}`}
                    >
                      <div>
                        <div className={`font-mono font-bold uppercase ${selectedProfile === profile.name ? 'text-primary' : 'text-foreground'}`}>
                          {profile.name}
                        </div>
                        <div className="text-xs text-muted-foreground font-mono mt-1 line-clamp-1">{profile.description}</div>
                      </div>
                      <ChevronRight className={`h-4 w-4 ${selectedProfile === profile.name ? 'text-primary' : 'text-muted-foreground'}`} />
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="md:col-span-2">
          {selectedProfile ? (
            <Card className="bg-card border-border rounded-none shadow-none min-h-[500px]">
              <CardHeader className="border-b border-border pb-4 bg-secondary/10">
                <CardTitle className="font-mono uppercase text-lg text-primary flex items-center gap-2">
                  <Shield className="h-5 w-5" /> Profile Ceilings: {selectedProfile}
                </CardTitle>
                <CardDescription className="font-mono text-xs">
                  Absolute limits that cannot be exceeded by any mandate using this profile.
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                {isCeilingsLoading ? (
                  <div className="p-8 text-center text-primary font-mono animate-pulse uppercase">Fetching ceilings...</div>
                ) : ceilings ? (
                  <table className="w-full text-sm text-left font-mono">
                    <thead className="text-xs text-muted-foreground uppercase bg-secondary/10 border-b border-border">
                      <tr>
                        <th className="px-6 py-3 font-medium">Property</th>
                        <th className="px-6 py-3 font-medium text-right">Maximum Ceiling</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">Min. Approval Mode</td>
                        <td className="px-6 py-4 text-right font-bold text-primary">{ceilings.min_approval_mode || 'N/A'}</td>
                      </tr>
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">Agent Delegation</td>
                        <td className="px-6 py-4 text-right">
                          <Badge variant="outline" className={`rounded-none font-mono text-[10px] uppercase ${ceilings.agent_delegation ? 'text-emerald-500 border-emerald-500/30' : 'text-destructive border-destructive/30'}`}>
                            {ceilings.agent_delegation ? 'ALLOWED' : 'FORBIDDEN'}
                          </Badge>
                        </td>
                      </tr>
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">Max Delegation Depth</td>
                        <td className="px-6 py-4 text-right font-bold">{ceilings.max_delegation_depth ?? 'N/A'}</td>
                      </tr>
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">Max Session Duration</td>
                        <td className="px-6 py-4 text-right font-bold">{ceilings.max_session_duration_minutes ? `${ceilings.max_session_duration_minutes} min` : 'UNLIMITED'}</td>
                      </tr>
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">Max Tool Calls</td>
                        <td className="px-6 py-4 text-right font-bold">{ceilings.max_tool_calls ?? 'UNLIMITED'}</td>
                      </tr>
                      
                      <tr className="bg-secondary/5 border-t border-border">
                        <td colSpan={2} className="px-6 py-2 text-xs font-bold uppercase text-primary tracking-widest"><Database className="inline h-3 w-3 mr-1" /> Platform Boundaries</td>
                      </tr>
                      
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">Shell Mode</td>
                        <td className="px-6 py-4 text-right font-bold">{ceilings.shell_mode || 'ANY'}</td>
                      </tr>
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">DB Production Access</td>
                        <td className="px-6 py-4 text-right">
                          <Badge variant="outline" className={`rounded-none font-mono text-[10px] uppercase ${ceilings.db_production ? 'text-emerald-500 border-emerald-500/30' : 'text-destructive border-destructive/30'}`}>
                            {ceilings.db_production ? 'ALLOWED' : 'FORBIDDEN'}
                          </Badge>
                        </td>
                      </tr>
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">DB Write Access</td>
                        <td className="px-6 py-4 text-right">
                          <Badge variant="outline" className={`rounded-none font-mono text-[10px] uppercase ${ceilings.db_write ? 'text-emerald-500 border-emerald-500/30' : 'text-destructive border-destructive/30'}`}>
                            {ceilings.db_write ? 'ALLOWED' : 'FORBIDDEN'}
                          </Badge>
                        </td>
                      </tr>
                      <tr className="hover:bg-secondary/20">
                        <td className="px-6 py-4 text-muted-foreground uppercase">Secrets Read</td>
                        <td className="px-6 py-4 text-right">
                          <Badge variant="outline" className={`rounded-none font-mono text-[10px] uppercase ${ceilings.secrets_read ? 'text-emerald-500 border-emerald-500/30' : 'text-destructive border-destructive/30'}`}>
                            {ceilings.secrets_read ? 'ALLOWED' : 'FORBIDDEN'}
                          </Badge>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                ) : (
                  <div className="p-8 text-center text-muted-foreground font-mono">No ceiling data available.</div>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card className="bg-card border-border rounded-none shadow-none h-full flex flex-col items-center justify-center p-8 text-center min-h-[500px]">
              <Shield className="h-12 w-12 text-muted-foreground/30 mb-4" />
              <CardTitle className="font-mono uppercase text-muted-foreground mb-2">No Profile Selected</CardTitle>
              <CardDescription className="font-mono text-xs max-w-sm">
                Select a governance profile from the list to view its absolute operational ceilings and platform boundaries.
              </CardDescription>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}