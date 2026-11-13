import { NavLink, Route, Routes, Navigate } from 'react-router-dom';
import { FirmwareProvider } from './store';
import { LibraryPage } from './pages/LibraryPage';
import { StructurePage } from './pages/StructurePage';
import { FileSystemPage } from './pages/FileSystemPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportPage } from './pages/ReportPage';

const NAV = [
  { to: '/library', label: '固件库', ico: '🗄' },
  { to: '/structure', label: '结构解析', ico: '🧩' },
  { to: '/filesystem', label: '文件系统', ico: '📁' },
  { to: '/findings', label: '风险发现', ico: '🛡' },
  { to: '/report', label: '报告 / 对比', ico: '📄' },
];

export function App() {
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="logo">
          固件分析台
          <small>Firmware Bench · 全本地运行</small>
        </div>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="ico">{n.ico}</span>
            {n.label}
          </NavLink>
        ))}
        <div className="side-foot">
          镜像与分析数据仅保存在本机 data/ 目录,不发起任何网络请求。
        </div>
      </aside>
      <main className="main">
        <FirmwareProvider>
          <Routes>
            <Route path="/" element={<Navigate to="/library" replace />} />
            <Route path="/library" element={<LibraryPage />} />
            <Route path="/structure" element={<StructurePage />} />
            <Route path="/filesystem" element={<FileSystemPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/report" element={<ReportPage />} />
          </Routes>
        </FirmwareProvider>
      </main>
    </div>
  );
}
