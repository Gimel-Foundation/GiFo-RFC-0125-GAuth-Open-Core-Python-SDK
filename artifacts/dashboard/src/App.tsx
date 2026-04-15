import { Switch, Route, Router as WouterRouter, useLocation } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import { AuthProvider, useAuth } from "@/lib/auth";
import AuthPage from "@/pages/auth";
import { Layout } from "@/components/layout";
import Dashboard from "@/pages/dashboard";
import MandatesPage from "@/pages/mandates";
import MandateDetailPage from "@/pages/mandate-detail";
import ProfilesPage from "@/pages/profiles";
import CredentialsPage from "@/pages/credentials";
import PoaMapPage from "@/pages/poa-map";
import { ComponentType } from "react";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    }
  }
});

function ProtectedRoute({ component: Component }: { component: ComponentType }) {
  const { isAuthenticated } = useAuth();
  const [, setLocation] = useLocation();

  if (!isAuthenticated) {
    setLocation("/login");
    return null;
  }

  return (
    <Layout>
      <Component />
    </Layout>
  );
}

function Router() {
  return (
    <Switch>
      <Route path="/login" component={AuthPage} />
      <Route path="/" component={() => <ProtectedRoute component={Dashboard} />} />
      <Route path="/mandates" component={() => <ProtectedRoute component={MandatesPage} />} />
      <Route path="/mandates/:id" component={() => <ProtectedRoute component={MandateDetailPage} />} />
      <Route path="/profiles" component={() => <ProtectedRoute component={ProfilesPage} />} />
      <Route path="/credentials" component={() => <ProtectedRoute component={CredentialsPage} />} />
      <Route path="/poa-map" component={() => <ProtectedRoute component={PoaMapPage} />} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TooltipProvider>
          <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
            <Router />
          </WouterRouter>
          <Toaster />
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
