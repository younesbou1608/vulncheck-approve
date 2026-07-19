import { Route, Routes } from "react-router-dom";
import Sidebar from "./components/Sidebar.jsx";
import ValidatePage from "./pages/ValidatePage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import ValidationDetailPage from "./pages/ValidationDetailPage.jsx";
import CvesPage from "./pages/CvesPage.jsx";
import CveDetailPage from "./pages/CveDetailPage.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";
import ModelPage from "./pages/ModelPage.jsx";
import { EmptyState } from "./components/DataStates.jsx";

export default function App() {
  return (
    <div className="shell">
      <Sidebar />
      <main className="main">
        <Routes>
          <Route path="/" element={<ValidatePage />} />
          <Route path="/historique" element={<HistoryPage />} />
          <Route path="/historique/:id" element={<ValidationDetailPage />} />
          <Route path="/cves" element={<CvesPage />} />
          <Route path="/cves/:cveId" element={<CveDetailPage />} />
          <Route path="/tableau-de-bord" element={<DashboardPage />} />
          <Route path="/modele" element={<ModelPage />} />
          <Route path="*" element={
            <EmptyState title="Page introuvable">
              Cette adresse ne correspond à aucun écran de la console.
            </EmptyState>
          } />
        </Routes>
      </main>
    </div>
  );
}
