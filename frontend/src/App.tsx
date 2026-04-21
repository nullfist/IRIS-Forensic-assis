import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import CasesPage from './pages/CasesPage';
import NewCasePage from './pages/NewCasePage';
import IncidentWorkbench from './pages/IncidentWorkbench';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/cases" replace />} />
        <Route path="/cases" element={<CasesPage />} />
        <Route path="/cases/new" element={<NewCasePage />} />
        <Route path="/cases/:caseId" element={<IncidentWorkbench />} />
        <Route path="*" element={<Navigate to="/cases" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
