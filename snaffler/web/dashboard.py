"""Dashboard HTML renderer — reads template from static/dashboard.html."""

from pathlib import Path

_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATE = None


def _load_template():
    global _TEMPLATE
    if _TEMPLATE is None:
        _TEMPLATE = (_STATIC_DIR / "dashboard.html").read_text()
    return _TEMPLATE


def render_dashboard(mode: str = "live") -> str:
    """Return a complete HTML page for the web dashboard."""
    title = "Snaffler Results" if mode == "results" else "Snaffler Live"
    footer_mode = "results" if mode == "results" else "live"
    body_attrs = ' data-mode="results"' if mode == "results" else ""

    html = _load_template()
    html = html.replace("{{TITLE}}", title)
    html = html.replace("{{BODY_ATTRS}}", body_attrs)
    html = html.replace("{{FOOTER_MODE}}", footer_mode)
    html = html.replace("{{MODE}}", mode)
    return html
