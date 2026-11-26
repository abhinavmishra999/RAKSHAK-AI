import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api, setCsrf } from "./api";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import Tests from "./pages/Tests";
import RunDetail from "./pages/RunDetail";
import Protection from "./pages/Protection";
import Activity from "./pages/Activity";
import Memory from "./pages/Memory";
import Guide from "./pages/Guide";
import Learn from "./pages/Learn";
import Login from "./pages/Login";

export default function App() {
  const [user, setUser] = useState(undefined);
  const check = useCallback(async () => {
    try {
      const me = await api("/auth/me");
      setCsrf(me.csrf);
      setUser(me);
    } catch {
      setCsrf("");
      setUser(null);
    }
  }, []);
  useEffect(() => {
    check();
    const out = () => { setCsrf(""); setUser(null); };
    window.addEventListener("rakshak:signed-out", out);
    return () => window.removeEventListener("rakshak:signed-out", out);
  }, [check]);

  if (user === undefined) return <div className="grid h-full place-items-center text-sm text-ink-400">Connecting to the local engine...</div>;
  if (!user) return <Login onSignedIn={(u) => { setCsrf(u.csrf); setUser(u); }} />;
  return (
    <Layout user={user} onSignOut={() => { setCsrf(""); setUser(null); }}>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:id" element={<AlertDetail />} />
        <Route path="/tests" element={<Tests />} />
        <Route path="/tests/:id" element={<RunDetail />} />
        <Route path="/check" element={<Navigate to="/tests" replace />} />
        <Route path="/protection" element={<Protection />} />
        <Route path="/activity" element={<Activity />} />
        <Route path="/memory" element={<Memory />} />
        <Route path="/guide" element={<Guide />} />
        <Route path="/learn" element={<Learn />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
