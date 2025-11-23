import { useEffect, useState } from "react";
import { getRequests, createRequest } from "../api/request";

export default function Dashboard({ token }: { token: string }) {
  const [requests, setRequests] = useState<any[]>([]);
  const [benefit, setBenefit] = useState("");

  useEffect(() => {
    getRequests(token).then(setRequests);
  }, [token]);

  async function handleCreate() {
    const res = await createRequest(token, benefit);
    setRequests([res, ...requests]);
    setBenefit("");
  }

  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold text-primary mb-6">Solicitudes de Beneficios</h1>
      <div className="flex gap-2 mb-4">
        <input className="border p-2 flex-1" placeholder="Tipo de beneficio" value={benefit} onChange={e => setBenefit(e.target.value)} />
        <button onClick={handleCreate} className="bg-primary text-white px-4 py-2 rounded">Solicitar</button>
      </div>
      <ul>
        {requests.map(r => (
          <li key={r.id} className="border-b py-2">
            <span className="font-semibold">{r.benefit_type}</span> - {r.status} ({new Date(r.created_at).toLocaleDateString()})
          </li>
        ))}
      </ul>
    </div>
  );
}