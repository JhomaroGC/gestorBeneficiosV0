import { useState } from "react";
import LoginPage from "./pages/LoginPage";
import Dashboard from "./pages/Dashboard";

function App() {
  const [token, setToken] = useState<string | null>(null);
  return token ? <Dashboard token={token} /> : <LoginPage onLogin={setToken} />;
}
export default App;
