import api from "./client";

export async function getRequests(token: string) {
  const res = await api.get("/request", {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}

export async function createRequest(token: string, benefit_type: string) {
  const res = await api.post("/request", { benefit_type }, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}