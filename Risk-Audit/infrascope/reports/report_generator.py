from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

from infrascope.models import Host, Finding


class ReportGenerator:
    def __init__(self, template_dir: str | Path | None = None):
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"
        self.template_dir = Path(template_dir)
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate_html(
        self,
        client_name: str,
        hosts: List[Host],
        findings: List[Finding],
        score: Dict[str, Any],
        output_path: str | Path,
        diagram_text: str = "",
    ) -> Path:
        template = self.env.get_template("client_report.html")
        html = template.render(
            client_name=client_name,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            hosts=hosts,
            findings=findings,
            score=score,
            diagram_text=diagram_text,
        )
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding="utf-8")
        return output
