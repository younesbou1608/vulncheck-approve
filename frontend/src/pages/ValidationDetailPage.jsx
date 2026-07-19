import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client.js";
import ValidationReport from "../components/ValidationReport.jsx";
import { ErrorState, Loading } from "../components/DataStates.jsx";

export default function ValidationDetailPage() {
  const { id } = useParams();
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setReport(null);
    setError(null);
    api.getValidation(id).then(setReport).catch(setError);
  }, [id]);

  return (
    <>
      <div className="page-head">
        <h1>Validation #{id}</h1>
        <p><Link to="/historique">← Retour à l'historique</Link></p>
      </div>
      {error ? <ErrorState error={error} /> : report ? <ValidationReport report={report} /> : <Loading />}
    </>
  );
}
