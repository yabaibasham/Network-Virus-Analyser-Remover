import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import Dashboard from "@/pages/Dashboard";

function App() {
  return (
    <div className="App grain">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
        </Routes>
      </BrowserRouter>
      <Toaster
        theme="dark"
        position="bottom-right"
        toastOptions={{
          style: {
            background: "#111",
            border: "1px solid #222",
            borderRadius: 0,
            color: "#fff",
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
          },
        }}
      />
    </div>
  );
}

export default App;
