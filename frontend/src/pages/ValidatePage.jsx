import { useEffect, useRef, useState } from "react";
import { api } from "../api/client.js";
import ValidationReport from "../components/ValidationReport.jsx";
import { Loading } from "../components/DataStates.jsx";

/* Page principale : formulaire de validation + rapport de conformité. */
export default function ValidatePage() {
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [suggestions, setSuggestions] = useState([]);
  const [showList, setShowList] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const debounce = useRef(null);
  const comboRef = useRef(null);

  /* Autocomplétion sur les produits CPE connus (min. 2 caractères). */
  useEffect(() => {
    clearTimeout(debounce.current);
    const q = name.trim();
    if (q.length < 2) { setSuggestions([]); return; }
    debounce.current = setTimeout(() => {
      api.suggestions(q)
        .then((rows) => { setSuggestions(rows); setShowList(true); })
        .catch(() => setSuggestions([]));
    }, 250);
    return () => clearTimeout(debounce.current);
  }, [name]);

  useEffect(() => {
    const close = (e) => {
      if (comboRef.current && !comboRef.current.contains(e.target)) setShowList(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const submit = (e) => {
    e.preventDefault();
    if (!name.trim() || loading) return;
    setLoading(true);
    setError(null);
    setReport(null);
    setShowList(false);
    api.createValidation(name.trim(), version.trim())
      .then(setReport)
      .catch(setError)
      .finally(() => setLoading(false));
  };

  return (
    <>
      <div className="page-head">
        <h1>Valider un logiciel</h1>
        <p>
          Vérifiez un logiciel tiers avant installation : identification du produit CPE,
          vulnérabilités applicables à la version, score de risque et verdict.
        </p>
      </div>

      <form className="card card-pad" onSubmit={submit}>
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <div className="field combo" style={{ flex: 2 }} ref={comboRef}>
            <label htmlFor="software-name">
              Nom du logiciel <span className="hint">(ex : AnyDesk, log4j, 7-Zip)</span>
            </label>
            <input
              id="software-name" type="text" value={name} autoComplete="off"
              onChange={(e) => setName(e.target.value)}
              onFocus={() => suggestions.length && setShowList(true)}
              placeholder="Nom commercial ou produit CPE"
              required maxLength={200}
            />
            {showList && suggestions.length > 0 && (
              <ul className="combo-list" role="listbox">
                {suggestions.map((s, i) => (
                  <li key={i} role="option" aria-selected="false"
                    onClick={() => { setName(s.product); setShowList(false); }}>
                    <span className="mono">{s.product}</span>
                    <span className="vendor">{s.vendor || ""}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="field" style={{ flex: 1 }}>
            <label htmlFor="software-version">
              Version <span className="hint">(vide = toutes versions)</span>
            </label>
            <input
              id="software-version" type="text" value={version} autoComplete="off"
              onChange={(e) => setVersion(e.target.value)}
              placeholder="7.0.4" maxLength={100}
            />
          </div>
          <button className="btn" type="submit" disabled={loading || !name.trim()}>
            {loading ? "Analyse en cours…" : "Lancer la validation"}
          </button>
        </div>
        {error && (
          <div className="error-box" style={{ marginTop: 16 }}>
            {error.message}
          </div>
        )}
      </form>

      <div style={{ marginTop: 20 }}>
        {loading && <Loading label="Matching, scoring et décision en cours…" />}
        {report && <ValidationReport report={report} />}
      </div>
    </>
  );
}
