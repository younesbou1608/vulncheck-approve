/* Client API : contrat aligné sur les schémas Pydantic du backend. */
const BASE = import.meta.env.VITE_API_URL || "";

async function request(path, options = {}) {
  const response = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    let detail = `Erreur ${response.status}`;
    try {
      const body = await response.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : detail;
    } catch { /* réponse non JSON */ }
    const err = new Error(detail);
    err.status = response.status;
    throw err;
  }
  return response.json();
}

export const api = {
  health: () => request("/health"),

  createValidation: (softwareName, softwareVersion) =>
    request("/api/v1/validations", {
      method: "POST",
      body: JSON.stringify({
        software_name: softwareName,
        software_version: softwareVersion || null,
      }),
    }),
  getValidation: (id) => request(`/api/v1/validations/${id}`),
  listValidations: ({ limit = 20, offset = 0, verdict = "" } = {}) => {
    const params = new URLSearchParams({ limit, offset });
    if (verdict) params.set("verdict", verdict);
    return request(`/api/v1/validations?${params}`);
  },
  suggestions: (q) =>
    request(`/api/v1/validations/suggestions?q=${encodeURIComponent(q)}`),

  searchCves: (q, limit = 20) =>
    request(`/api/v1/cves?q=${encodeURIComponent(q)}&limit=${limit}`),
  getCve: (cveId) => request(`/api/v1/cves/${encodeURIComponent(cveId)}`),

  statsOverview: () => request("/api/v1/stats/overview"),
  modelInfo: () => request("/api/v1/model/info"),
};
