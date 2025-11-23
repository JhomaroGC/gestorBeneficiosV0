import { useState } from "react";
import { login } from "../api/auth";

export default function LoginPage({ onLogin }: { onLogin: (token: string) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    try {
      const res = await login({ email, password });
      onLogin(res.access_token);
    } catch {
      alert("Credenciales incorrectas");
    }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-primary text-white">
      <form onSubmit={handleSubmit} className="bg-white p-8 rounded shadow-md w-96 text-gray-900">
        <h1 className="text-2xl font-bold mb-4 text-primary">Iniciar Sesión</h1>
        <input className="border p-2 w-full mb-4" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
        <input className="border p-2 w-full mb-4" type="password" placeholder="Contraseña" value={password} onChange={e => setPassword(e.target.value)} />
        <button className="bg-primary text-white px-4 py-2 rounded w-full">Entrar</button>
      </form>
    </div>
  );
}