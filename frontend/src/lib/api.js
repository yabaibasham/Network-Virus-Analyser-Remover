import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API = `${BACKEND_URL}/api`;

export const api = axios.create({ baseURL: API, timeout: 60000 });

export const fetchDevices = () => api.get("/devices").then((r) => r.data);
export const fetchDevice = (id) => api.get(`/devices/${id}`).then((r) => r.data);
export const fetchDeviceSurface = (id) =>
  api.get(`/devices/${id}/surface`).then((r) => r.data);
export const deviceAction = (id, action) =>
  api.post(`/devices/${id}/action`, { action }).then((r) => r.data);
export const fetchThreatLogs = (limit = 50) =>
  api.get(`/threat-logs?limit=${limit}`).then((r) => r.data);
export const fetchStats = () => api.get("/stats").then((r) => r.data);
export const runScan = (payload) => api.post("/scan", payload).then((r) => r.data);
export const uploadScan = (file) => {
  const fd = new FormData();
  fd.append("file", file);
  return api
    .post("/scan/upload", fd, { headers: { "Content-Type": "multipart/form-data" } })
    .then((r) => r.data);
};
export const fetchScans = (limit = 25) =>
  api.get(`/scans?limit=${limit}`).then((r) => r.data);

export const reportMissing = (id, payload) =>
  api.post(`/devices/${id}/report-missing`, payload).then((r) => r.data);
export const markRecovered = (id) =>
  api.post(`/devices/${id}/mark-recovered`).then((r) => r.data);

export const fetchIncidents = (limit = 50) =>
  api.get(`/incidents?limit=${limit}`).then((r) => r.data);
export const updateIncidentStatus = (id, status) =>
  api.post(`/incidents/${id}/status`, { status }).then((r) => r.data);
