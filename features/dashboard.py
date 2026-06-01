# Minimal dashboard helper for CLI-based single-pane control

from typing import Optional

class Dashboard:
    def render(self, status: Optional[str] = None):
        s = status or "idle"
        panel = f"""
┌───────────────────────────────┐
│   🟢 OMNISIGHT CONTROL PANEL  │
├───────────────────────────────┤
│ [SCAN] [MONITOR] [LIVE] [PLUGINS]
├───────────────────────────────┤
│ Status: {s}
├───────────────────────────────┤
│ Actions:
│  - Start Quick Scan
│  - Start Selective Scan
│  - Add Monitor
│  - Run Live Scan
└───────────────────────────────┘
"""
        print(panel)

