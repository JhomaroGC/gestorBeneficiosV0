import api from "./client";

export async function register(data: {name: string; email: string; password: string; rol: string}) {
  const res = await api.post("/register", data);
  return res.data;
}

export async function login(data: {email: string; password: string}) {
  const res = await api.post("/login", data);
  return res.data;
}