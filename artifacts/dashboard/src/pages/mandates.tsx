import { useListMandates } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useState } from "react";
import { format } from "date-fns";
import { MandateStatus, GovernanceProfile } from "@workspace/api-client-react";

export default function MandatesPage() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [profileFilter, setProfileFilter] = useState<string>("all");
  const [subjectFilter, setSubjectFilter] = useState("");

  const { data, isLoading } = useListMandates({
    limit: 100,
    status: statusFilter !== "all" ? statusFilter as MandateStatus : undefined,
    governance_profile: profileFilter !== "all" ? profileFilter as GovernanceProfile : undefined,
  });

  const mandates = data?.items || [];
  
  // Client side subject filter
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

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1">Mandates</h1>
          <p className="text-muted-foreground font-mono text-sm">Active and historical Power of Attorney authorizations.</p>
        </div>
        <div className="flex gap-2">
          {/* Note: Create feature could be added here if needed */}
        </div>
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
              />
            </div>
            <div className="w-full sm:w-48">
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="font-mono rounded-none border-border bg-background focus:ring-primary">
                  <SelectValue placeholder="All Statuses" />
                </SelectTrigger>
                <SelectContent className="rounded-none border-border">
                  <SelectItem value="all">All Statuses</SelectItem>
                  {Object.values(MandateStatus).map((status) => (
                    <SelectItem key={status} value={status}>{status}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="w-full sm:w-48">
              <Select value={profileFilter} onValueChange={setProfileFilter}>
                <SelectTrigger className="font-mono rounded-none border-border bg-background focus:ring-primary">
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
                  <th className="px-4 py-3 font-medium">Updated</th>
                  <th className="px-4 py-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {isLoading ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">Loading mandates...</td>
                  </tr>
                ) : filteredMandates.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">No mandates found matching filters.</td>
                  </tr>
                ) : (
                  filteredMandates.map((mandate) => (
                    <tr key={mandate.mandate_id} className="hover:bg-secondary/30 transition-colors">
                      <td className="px-4 py-3">
                        <div className="font-bold text-primary">{mandate.mandate_id.split('-')[0]}</div>
                        <div className="text-xs text-muted-foreground">{mandate.parties.subject}</div>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className={`rounded-none font-mono text-[10px] ${getStatusColor(mandate.status)}`}>
                          {mandate.status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-xs uppercase">{mandate.governance_profile}</td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {format(new Date(mandate.updated_at), 'yyyy-MM-dd HH:mm')}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link href={`/mandates/${mandate.mandate_id}`}>
                          <Button variant="outline" size="sm" className="rounded-none font-mono text-xs h-7 hover:bg-primary hover:text-primary-foreground border-primary/30">
                            Details
                          </Button>
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}