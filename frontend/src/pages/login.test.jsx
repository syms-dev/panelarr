import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/hooks/use-auth";

import Login from "./login";

function mockBackend(status, onLogin) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
    const json = (code, body) =>
      new Response(JSON.stringify(body), { status: code, headers: { "Content-Type": "application/json" } });
    if (url === "/api/auth/status") return json(200, status.current);
    if (url === "/api/auth/login") {
      onLogin(JSON.parse(init.body));
      status.current = { ...status.current, authenticated: true };
      return json(200, { ok: true });
    }
    return json(404, {});
  });
}

function Where() {
  const loc = useLocation();
  return <div data-testid="where">{loc.pathname}</div>;
}

function renderLogin(entry) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <MemoryRouter initialEntries={[entry]}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="*" element={<Where />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("Login page", () => {
  afterEach(() => vi.restoreAllMocks());

  it("renders username/password in basic mode and honours ?next=", async () => {
    const login = vi.fn();
    mockBackend({ current: { mode: "basic", authenticated: false } }, login);
    renderLogin("/login?next=%2Fmovies");
    await userEvent.type(await screen.findByLabelText("Username"), "admin");
    await userEvent.type(screen.getByLabelText("Password"), "pw");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/movies"));
    expect(login).toHaveBeenCalledWith({ username: "admin", password: "pw" });
  });

  it("renders only an API-key field in apikey mode", async () => {
    const login = vi.fn();
    mockBackend({ current: { mode: "apikey", authenticated: false } }, login);
    renderLogin("/login");
    const field = await screen.findByLabelText("API key");
    expect(screen.queryByLabelText("Username")).toBeNull();
    await userEvent.type(field, "secret-key");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => expect(login).toHaveBeenCalledWith({ api_key: "secret-key" }));
  });

  it("ignores an unsafe ?next= value", async () => {
    const login = vi.fn();
    mockBackend({ current: { mode: "basic", authenticated: false } }, login);
    renderLogin("/login?next=%2F%2Fevil.com");
    await userEvent.type(await screen.findByLabelText("Username"), "a");
    await userEvent.type(screen.getByLabelText("Password"), "b");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/"));
  });
});
