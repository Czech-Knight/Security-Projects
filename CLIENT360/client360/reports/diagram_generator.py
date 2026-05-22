from pathlib import Path
from typing import Dict


def generate_mermaid_diagram(config: Dict, output_path: str) -> Path:
    client_name = config.get("client", {}).get("name", "Client")
    content = f"""# Client360 Architecture Diagram

```mermaid
flowchart TD
    A[Support Engineer] --> B[Client360 Streamlit Dashboard]
    B --> C[Microsoft 365 Audit Module]
    B --> D[Azure/AWS Cloud Review]
    B --> E[Firewall Rule Review]
    B --> F[Network/Subnet Documentation]
    B --> G[Backup & DR Health Check]
    C --> H[Risk Engine]
    D --> H
    E --> H
    F --> H
    G --> H
    H --> I[Client-Ready HTML/PDF Report]
    H --> J[Remediation Summary]
    B --> K[Documentation Diagram]
```

Client: {client_name}
"""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
