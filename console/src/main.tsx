import { Component, StrictMode } from "react";
import type { ReactNode, ErrorInfo } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import "./style.css";
class Boundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch(_error: Error, _info: ErrorInfo) {
    /* Never send server data or credentials to browser telemetry. */
  }
  render() {
    return this.state.failed ? (
      <main className="login">
        <h1>控制台加载失败</h1>
        <p>刷新页面后重试。若持续失败，请联系管理员检查构建和浏览器兼容性。</p>
        <button onClick={() => location.reload()}>刷新</button>
      </main>
    ) : (
      this.props.children
    );
  }
}
const root = document.getElementById("root");
if (!root) throw new Error("Missing console root");
createRoot(root).render(
  <StrictMode>
    <Boundary>
      <App />
    </Boundary>
  </StrictMode>,
);
