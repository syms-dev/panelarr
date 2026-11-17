import { Suspense, lazy } from "react";
import { Navigate, Outlet, createBrowserRouter, useLocation } from "react-router-dom";

import Layout from "@/components/layout";
import ErrorBoundary, { RootErrorBoundary } from "@/components/error-boundary";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { safeNextPath } from "@/lib/api";
import { useAuth } from "@/hooks/use-auth";
import { useSetupStatus } from "@/hooks/use-setup-status";

const Login = lazy(() => import("@/pages/login"));
const Dashboard = lazy(() => import("@/pages/dashboard"));
const Calendar = lazy(() => import("@/pages/calendar"));
const Containers = lazy(() => import("@/pages/containers"));
const Downloads = lazy(() => import("@/pages/downloads"));
const MovieDetail = lazy(() => import("@/pages/movie-detail"));
const Movies = lazy(() => import("@/pages/movies"));
const Settings = lazy(() => import("@/pages/settings"));
const ShowDetail = lazy(() => import("@/pages/show-detail"));
const Shows = lazy(() => import("@/pages/shows"));

// Setup wizard pages, lazy loaded, outside RequireAuth
const WizardLayout = lazy(() => import("@/components/wizard-layout"));
const SetupWelcome = lazy(() => import("@/pages/setup/welcome"));
const SetupSystemCheck = lazy(() => import("@/pages/setup/system-check"));
const SetupAuth = lazy(() => import("@/pages/setup/auth"));
const SetupDiscover = lazy(() => import("@/pages/setup/discover"));
const SetupServices = lazy(() => import("@/pages/setup/services"));
const SetupNotifications = lazy(() => import("@/pages/setup/notifications"));
const SetupThresholds = lazy(() => import("@/pages/setup/thresholds"));
const SetupDone = lazy(() => import("@/pages/setup/done"));

const PAGE_SPINNER = (
  <div className="flex min-h-screen items-center justify-center">
    <Spinner className="size-8" />
  </div>
);

function RequireSetup() {
  const { data, isLoading, isError, error, refetch, isFetching } = useSetupStatus();
  const { pathname } = useLocation();
  const isUnderSetup = pathname.startsWith("/setup");

  if (isLoading) {
    return PAGE_SPINNER;
  }

  // A failed status check is NOT "setup incomplete": show a retry state
  // instead of bouncing the user into the wizard.
  if (isError || !data) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-4 text-center">
        <p className="font-medium">Could not load Panelarr status</p>
        <p className="text-sm text-muted-foreground">{error?.message || "The server did not respond."}</p>
        <Button onClick={() => refetch()} loading={isFetching}>
          Retry
        </Button>
      </div>
    );
  }

  // If setup not complete and user is not already on /setup, redirect there
  if (!data?.setup_complete && !isUnderSetup) {
    return <Navigate to="/setup" replace />;
  }

  // If setup is complete and user tries to visit /setup, redirect to dashboard
  if (data?.setup_complete && isUnderSetup) {
    return <Navigate to="/" replace />;
  }

  return <Outlet />;
}

function RequireAuth() {
  const { mode, isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return PAGE_SPINNER;
  }

  // No auth needed for these modes
  if (mode === "none" || mode === "proxy") {
    return <Outlet />;
  }

  // Auth required but not authenticated
  if (!isAuthenticated) {
    const here = `${location.pathname}${location.search}${location.hash}`;
    const next = safeNextPath(here);
    return (
      <Navigate to={next && next !== "/" ? `/login?next=${encodeURIComponent(next)}` : "/login"} replace />
    );
  }

  return <Outlet />;
}

export const router = createBrowserRouter([
  {
    errorElement: <RootErrorBoundary />,
    children: [
      {
        path: "login",
        element: (
          <Suspense fallback={PAGE_SPINNER}>
            <Login />
          </Suspense>
        ),
      },
      {
        element: <RequireSetup />,
        children: [
          // Setup wizard, outside RequireAuth, uses WizardLayout
          {
            path: "setup",
            element: (
              <Suspense fallback={PAGE_SPINNER}>
                <WizardLayout />
              </Suspense>
            ),
            children: [
              { index: true, element: <Navigate to="/setup/welcome" replace /> },
              {
                path: "welcome",
                element: (
                  <Suspense fallback={PAGE_SPINNER}>
                    <SetupWelcome />
                  </Suspense>
                ),
              },
              {
                path: "system-check",
                element: (
                  <Suspense fallback={PAGE_SPINNER}>
                    <SetupSystemCheck />
                  </Suspense>
                ),
              },
              {
                path: "auth",
                element: (
                  <Suspense fallback={PAGE_SPINNER}>
                    <SetupAuth />
                  </Suspense>
                ),
              },
              {
                path: "discover",
                element: (
                  <Suspense fallback={PAGE_SPINNER}>
                    <SetupDiscover />
                  </Suspense>
                ),
              },
              {
                path: "services",
                element: (
                  <Suspense fallback={PAGE_SPINNER}>
                    <SetupServices />
                  </Suspense>
                ),
              },
              {
                path: "notifications",
                element: (
                  <Suspense fallback={PAGE_SPINNER}>
                    <SetupNotifications />
                  </Suspense>
                ),
              },
              {
                path: "thresholds",
                element: (
                  <Suspense fallback={PAGE_SPINNER}>
                    <SetupThresholds />
                  </Suspense>
                ),
              },
              {
                path: "done",
                element: (
                  <Suspense fallback={PAGE_SPINNER}>
                    <SetupDone />
                  </Suspense>
                ),
              },
            ],
          },
          // Main app, inside RequireAuth
          {
            element: <RequireAuth />,
            children: [
              {
                element: <Layout />,
                errorElement: <ErrorBoundary />,
                children: [
                  { index: true, element: <Dashboard /> },
                  { path: "movies", element: <Movies /> },
                  { path: "movies/:id", element: <MovieDetail /> },
                  { path: "shows", element: <Shows /> },
                  { path: "shows/:id", element: <ShowDetail /> },
                  { path: "calendar", element: <Calendar /> },
                  { path: "containers", element: <Containers /> },
                  { path: "downloads", element: <Downloads /> },
                  { path: "settings", element: <Settings /> },
                ],
              },
            ],
          },
        ],
      },
    ],
  },
]);
