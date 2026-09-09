import { useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import ChatPage from "./pages/ChatPage";
import DashboardPage from "./pages/DashboardPage";
import AttackSimulatorPage from "./pages/AttackSimulatorPage";
import EventsPage from "./pages/EventsPage";
import AlertsPage from "./pages/AlertsPage";
import PoliciesPage from "./pages/PoliciesPage";
import ModelPerformancePage from "./pages/ModelPerformancePage";
import SessionReplayPage from "./pages/SessionReplayPage";
import AgentTracePage from "./pages/AgentTracePage";

const NAV_ITEMS = [
  { to: "/", label: "Chat", end: true },
  { to: "/dashboard", label: "Dashboard" },
  { to: "/simulator", label: "Attack Simulator" },
  { to: "/events", label: "Events" },
  { to: "/alerts", label: "Alerts" },
  { to: "/policies", label: "Policies" },
  { to: "/trace", label: "Agent Trace" },
  { to: "/replay", label: "Session Replay" },
  { to: "/model-performance", label: "Model Performance" },
];

export default function App() {
  const [navOpen, setNavOpen] = useState(false);

  return (
    <div className="h-screen flex flex-col md:flex-row bg-slate-950 text-slate-100">
      {/* Mobile top bar: brand + hamburger toggle. Hidden at md and up,
          where the sidebar is always visible instead. */}
      <div className="md:hidden shrink-0 flex items-center justify-between px-4 py-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-bold text-sm shrink-0">
            AS
          </div>
          <div>
            <div className="font-semibold text-sm leading-tight">AI Agent Security</div>
            <div className="text-xs text-slate-500 leading-tight">Monitor</div>
          </div>
        </div>
        <button
          type="button"
          aria-label={navOpen ? "Close navigation" : "Open navigation"}
          onClick={() => setNavOpen((v) => !v)}
          className="h-9 w-9 flex items-center justify-center rounded-lg border border-slate-700 text-slate-300 hover:text-cyan-300 hover:border-cyan-600 transition-colors"
        >
          {navOpen ? (
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </button>
      </div>

      {/* Backdrop for the mobile drawer */}
      {navOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          onClick={() => setNavOpen(false)}
          aria-hidden="true"
        />
      )}

      <aside
        className={`w-64 md:w-60 shrink-0 border-r border-slate-800 flex flex-col bg-slate-950 fixed inset-y-0 left-0 z-40 transform transition-transform duration-200 ease-out md:static md:transform-none md:z-auto ${
          navOpen ? "translate-x-0" : "-translate-x-full"
        } md:translate-x-0`}
      >
        <div className="px-5 py-5 border-b border-slate-800 hidden md:block">
          <div className="flex items-center gap-2">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-bold text-sm">
              AS
            </div>
            <div>
              <div className="font-semibold text-sm leading-tight">AI Agent Security</div>
              <div className="text-xs text-slate-500 leading-tight">Monitor</div>
            </div>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setNavOpen(false)}
              className={({ isActive }) =>
                `block rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive ? "bg-cyan-500/15 text-cyan-300" : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-4 border-t border-slate-800 text-[11px] leading-relaxed text-slate-600">
          Simulated FinAssist agent. All data synthetic. No real emails, banking systems, or credentials are ever touched.
        </div>
      </aside>

      <main className="flex-1 min-w-0 min-h-0 overflow-y-auto">
        <Routes>
          <Route path="/" element={<ChatPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/simulator" element={<AttackSimulatorPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/trace" element={<AgentTracePage />} />
          <Route path="/replay" element={<SessionReplayPage />} />
          <Route path="/model-performance" element={<ModelPerformancePage />} />
        </Routes>
      </main>
    </div>
  );
}
