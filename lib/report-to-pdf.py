#!/usr/bin/env python3
"""
report-to-pdf.py — Convert InfoSec-Suite markdown report to PDF
Usage: python3 lib/report-to-pdf.py <report.md> [--output <report.pdf>]
Requires: pip3 install weasyprint markdown
"""

import sys
import os
import re
import argparse


CSS = """
/* ── Page setup ─────────────────────────────────────────────────────────── */
@page {
    size: A4;
    margin: 2.5cm 2cm 2.5cm 2.2cm;
    @bottom-left {
        content: "CONFIDENTIAL";
        font-family: 'Helvetica Neue', Arial, sans-serif;
        font-size: 8pt;
        color: #c0392b;
        letter-spacing: 1px;
        font-weight: bold;
    }
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-family: 'Helvetica Neue', Arial, sans-serif;
        font-size: 8pt;
        color: #888;
    }
    @bottom-right {
        content: string(report-client);
        font-family: 'Helvetica Neue', Arial, sans-serif;
        font-size: 8pt;
        color: #888;
    }
}

@page :first {
    @bottom-left   { content: ""; }
    @bottom-center { content: ""; }
    @bottom-right  { content: ""; }
}

/* ── Base ────────────────────────────────────────────────────────────────── */
* { box-sizing: border-box; }

body {
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 10.5pt;
    line-height: 1.65;
    color: #1a1a2e;
    background: #ffffff;
}

/* ── Cover page ──────────────────────────────────────────────────────────── */
.cover-page {
    page-break-after: always;
    min-height: 26cm;
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
    padding-top: 5cm;
}

.cover-client {
    font-size: 32pt;
    font-weight: 900;
    color: #1a1a2e;
    letter-spacing: 2px;
    border-bottom: 4px solid #c0392b;
    padding-bottom: 12px;
    margin-bottom: 8px;
    string-set: report-client content();
}

.cover-title {
    font-size: 18pt;
    font-weight: 300;
    color: #444;
    margin-bottom: 2.5cm;
}

.cover-date {
    font-size: 11pt;
    color: #666;
    margin-bottom: 1.5cm;
}

.cover-bar {
    width: 60px;
    height: 4px;
    background: #c0392b;
    margin-bottom: 1.5cm;
}

.cover-meta-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1.5cm;
    font-size: 10pt;
}

.cover-meta-table td {
    padding: 8px 12px;
    border-bottom: 1px solid #e8e8e8;
    vertical-align: top;
}

.cover-meta-table td:first-child {
    font-weight: bold;
    color: #555;
    width: 180px;
}

/* ── Headings ────────────────────────────────────────────────────────────── */
h1 {
    font-size: 22pt;
    font-weight: 900;
    color: #1a1a2e;
    border-bottom: 3px solid #c0392b;
    padding-bottom: 8px;
    margin: 0 0 4px 0;
}

h2 {
    font-size: 15pt;
    font-weight: 700;
    color: #1a1a2e;
    border-left: 4px solid #c0392b;
    padding-left: 10px;
    margin: 32px 0 12px 0;
    page-break-before: always;
}

/* Don't force page break on h2 directly after cover */
.no-break-before {
    page-break-before: avoid !important;
}

h3 {
    font-size: 12pt;
    font-weight: 700;
    color: #2c3e50;
    margin: 22px 0 8px 0;
    border-bottom: 1px solid #ecf0f1;
    padding-bottom: 4px;
}

h4 {
    font-size: 10.5pt;
    font-weight: 700;
    color: #34495e;
    margin: 16px 0 6px 0;
}

/* ── Body text ───────────────────────────────────────────────────────────── */
p {
    margin: 0 0 10px 0;
}

a {
    color: #2980b9;
    text-decoration: none;
}

strong {
    font-weight: 700;
    color: inherit;
}

em {
    font-style: italic;
    color: #555;
    font-size: 9.5pt;
}

/* ── Severity badges ─────────────────────────────────────────────────────── */
.sev-critical {
    background: #c0392b;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 9pt;
    font-weight: 700;
    letter-spacing: 0.3px;
}

.sev-high {
    background: #e67e22;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 9pt;
    font-weight: 700;
}

.sev-medium {
    background: #f39c12;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 9pt;
    font-weight: 700;
}

.sev-low {
    background: #3498db;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 9pt;
    font-weight: 700;
}

.sev-info {
    background: #95a5a6;
    color: #fff;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 9pt;
    font-weight: 700;
}

/* Risk label line in findings */
.risk-label {
    display: inline-block;
    font-weight: 700;
    color: #555;
    margin-right: 6px;
}

/* ── Tables ──────────────────────────────────────────────────────────────── */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0 16px 0;
    font-size: 9.5pt;
    page-break-inside: auto;
}

thead th {
    background: #2c3e50;
    color: #ffffff;
    padding: 8px 12px;
    text-align: left;
    font-weight: 700;
    font-size: 9pt;
    letter-spacing: 0.3px;
}

tbody tr:nth-child(odd)  td { background: #ffffff; }
tbody tr:nth-child(even) td { background: #f7f9fc; }

tbody td {
    padding: 7px 12px;
    border-bottom: 1px solid #e8ecf0;
    vertical-align: top;
    color: #1a1a2e;
}

/* Cover meta table overrides */
.cover-meta-table thead th { display: none; }

/* Severity summary bar */
.sev-bar {
    background: #f7f9fc;
    border: 1px solid #e0e6ed;
    border-radius: 5px;
    padding: 10px 16px;
    font-size: 10pt;
    margin: 10px 0 16px 0;
    font-weight: 600;
}

/* ── Code ────────────────────────────────────────────────────────────────── */
code {
    font-family: 'Courier New', 'Lucida Console', monospace;
    font-size: 8.5pt;
    background: #f0f2f5;
    color: #c0392b;
    padding: 1px 5px;
    border-radius: 3px;
    border: 1px solid #e0e4e9;
}

pre {
    background: #1e2430;
    color: #abb2bf;
    padding: 14px 16px;
    border-radius: 5px;
    font-family: 'Courier New', 'Lucida Console', monospace;
    font-size: 8.5pt;
    line-height: 1.5;
    page-break-inside: avoid;
    margin: 10px 0;
    overflow-wrap: break-word;
    white-space: pre-wrap;
}

pre code {
    background: none;
    color: #abb2bf;
    padding: 0;
    border: none;
    font-size: 8.5pt;
}

/* ── Blockquotes ─────────────────────────────────────────────────────────── */
blockquote {
    border-left: 4px solid #f39c12;
    background: #fffbf0;
    padding: 10px 14px;
    margin: 10px 0;
    font-size: 9.5pt;
    color: #555;
    page-break-inside: avoid;
}

blockquote p { margin: 0; }

/* ── Lists ───────────────────────────────────────────────────────────────── */
ul, ol {
    margin: 6px 0 10px 0;
    padding-left: 20px;
}

li {
    margin-bottom: 4px;
    font-size: 10.5pt;
}

/* ── Horizontal rules ────────────────────────────────────────────────────── */
hr {
    border: none;
    border-top: 2px solid #ecf0f1;
    margin: 20px 0;
}

/* ── Finding sections ────────────────────────────────────────────────────── */
.finding-block {
    page-break-inside: avoid;
    border: 1px solid #e0e6ed;
    border-left: 4px solid #e0e6ed;
    border-radius: 4px;
    padding: 14px 16px;
    margin: 14px 0;
}

.finding-block.sev-border-critical { border-left-color: #c0392b; }
.finding-block.sev-border-high     { border-left-color: #e67e22; }
.finding-block.sev-border-medium   { border-left-color: #f39c12; }
.finding-block.sev-border-low      { border-left-color: #3498db; }
.finding-block.sev-border-info     { border-left-color: #95a5a6; }

.finding-block h3 {
    margin-top: 0;
    border-bottom: 1px solid #ecf0f1;
}

/* ── Footer note ─────────────────────────────────────────────────────────── */
.report-footer {
    margin-top: 30px;
    padding-top: 10px;
    border-top: 1px solid #e0e6ed;
    font-size: 8.5pt;
    color: #888;
}
"""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
{css}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def add_severity_classes(html: str) -> str:
    """Wrap severity labels in styled <span> tags."""
    sev_map = {
        'Critical':      'sev-critical',
        'High':          'sev-high',
        'Medium':        'sev-medium',
        'Low':           'sev-low',
        'Informational': 'sev-info',
    }
    for label, cls in sev_map.items():
        # In bold tags (table cells, Risk: lines)
        html = html.replace(
            f'<strong>{label}</strong>',
            f'<strong class="{cls}">{label}</strong>'
        )
        # Plain text after "Risk: " in finding blocks
        html = re.sub(
            rf'(<strong>Risk:</strong>\s*){label}',
            rf'\1<strong class="{cls}">{label}</strong>',
            html
        )
        # In backtick spans: `Critical: N` in sev bar
        html = re.sub(
            rf'<code>\s*{label}:\s*(\d+)\s*</code>',
            rf'<span class="sev-bar"><strong class="{cls}">{label}</strong>: \1</span>',
            html
        )
    return html


def build_cover_page(html: str) -> str:
    """
    Detect the first H1 + H2 + metadata table and wrap them in a cover-page div.
    Everything before the first <h2 class="no-break-before"> (Confidentiality Statement)
    becomes the cover.
    """
    # Find the Confidentiality Statement h2 — that's where body content starts
    split_marker = re.search(
        r'<h2[^>]*>Confidentiality Statement</h2>', html, re.IGNORECASE)
    if not split_marker:
        # No split point found — wrap everything up to first h2 as cover
        split_marker = re.search(r'<h2', html)

    if not split_marker:
        return html  # Nothing to do

    cover_html  = html[:split_marker.start()]
    body_html   = html[split_marker.start():]

    # Transform H1 → cover-client, H2 under cover → cover-title
    cover_html = re.sub(
        r'<h1>(.*?)</h1>',
        r'<div class="cover-client">\1</div>',
        cover_html, flags=re.DOTALL
    )
    cover_html = re.sub(
        r'<h2>(.*?)</h2>',
        r'<div class="cover-title">\1</div>',
        cover_html, flags=re.DOTALL
    )

    # Make metadata table use cover-meta-table class
    cover_html = cover_html.replace('<table>', '<table class="cover-meta-table">', 1)

    # Mark the first h2 in body as no-break-before
    body_html = body_html.replace(
        split_marker.group(0),
        split_marker.group(0).replace('<h2', '<h2 class="no-break-before"', 1),
        1
    )

    return (
        f'<div class="cover-page">\n{cover_html}\n</div>\n'
        + body_html
    )


def wrap_finding_blocks(html: str) -> str:
    """
    Wrap each Technical Finding section (h3 + content up to next h3 or hr)
    in a .finding-block div with a severity-coloured left border.
    """
    sev_border = {
        'critical': 'sev-border-critical',
        'high':     'sev-border-high',
        'medium':   'sev-border-medium',
        'low':      'sev-border-low',
        'info':     'sev-border-info',
        'informational': 'sev-border-info',
    }

    def replace_finding(m):
        content = m.group(0)
        sev_cls = 'sev-border-info'
        for sev, cls in sev_border.items():
            if f'class="sev-{sev}"' in content.lower() or f'>{sev.title()}<' in content:
                sev_cls = cls
                break
        return f'<div class="finding-block {sev_cls}">\n{content}\n</div>'

    # Match h3 blocks (finding ID — Title) through to the next hr or h3 or h2
    html = re.sub(
        r'(<h3>[A-Z]{2}-[A-Z]{3}-\d{3}.*?</h3>.*?)(?=<h3>|<h2>|<hr\s*/?>|\Z)',
        replace_finding,
        html,
        flags=re.DOTALL
    )
    return html


def convert_md_to_pdf(md_path: str, pdf_path: str) -> bool:
    try:
        import markdown as md_lib
    except ImportError:
        print('[HALT] Python markdown package not installed. Run: pip3 install markdown')
        return False

    try:
        import weasyprint
    except ImportError:
        print('[HALT] weasyprint not installed. Run: pip3 install weasyprint')
        return False

    # Read markdown
    with open(md_path, 'r', encoding='utf-8') as f:
        md_source = f.read()

    # Convert to HTML
    extensions = [
        'tables',
        'fenced_code',
        'codehilite',
        'toc',
        'nl2br',
        'sane_lists',
    ]
    ext_configs = {
        'codehilite': {'noclasses': True, 'linenums': False},
        'toc': {'anchorlink': False},
    }

    try:
        body_html = md_lib.markdown(
            md_source,
            extensions=extensions,
            extension_configs=ext_configs,
        )
    except Exception:
        # Fall back to minimal extensions if codehilite isn't available
        body_html = md_lib.markdown(
            md_source,
            extensions=['tables', 'fenced_code', 'toc', 'sane_lists'],
        )

    # Post-process
    body_html = add_severity_classes(body_html)
    body_html = build_cover_page(body_html)
    body_html = wrap_finding_blocks(body_html)

    # Add footer class to last <p> containing "Generated by"
    body_html = re.sub(
        r'(<p><em>Generated by InfoSec-Suite.*?</em></p>)',
        r'<div class="report-footer">\1</div>',
        body_html,
        flags=re.DOTALL
    )

    # Extract title from first H1 / cover-client div
    title_match = re.search(r'<div class="cover-client">(.*?)</div>', body_html)
    title = title_match.group(1) if title_match else 'Pentest Report'
    title = re.sub(r'<[^>]+>', '', title).strip()  # strip any nested tags

    # Build full HTML document
    full_html = HTML_TEMPLATE.format(
        title=title,
        css=CSS,
        body=body_html,
    )

    # Write intermediate HTML (useful for debugging)
    html_path = pdf_path.replace('.pdf', '.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(full_html)

    # Convert to PDF
    print(f'[INFO] Converting to PDF via weasyprint...')
    try:
        wp = weasyprint.HTML(filename=html_path)
        wp.write_pdf(pdf_path)
        pdf_size = os.path.getsize(pdf_path) / 1024
        print(f'[OK]   PDF written → {pdf_path} ({pdf_size:.0f} KB)')
        return True
    except Exception as e:
        print(f'[FAIL] weasyprint error: {e}')
        print(f'       HTML saved → {html_path} (open in browser to inspect)')
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Convert InfoSec-Suite markdown report to PDF')
    parser.add_argument('input', help='Path to the .md report file')
    parser.add_argument('--output', '-o', help='Output PDF path (default: same name as input)')
    args = parser.parse_args()

    md_path = os.path.abspath(args.input)
    if not os.path.exists(md_path):
        print(f'[HALT] Input file not found: {md_path}')
        sys.exit(1)

    if args.output:
        pdf_path = os.path.abspath(args.output)
    else:
        pdf_path = md_path.replace('.md', '.pdf')
        if pdf_path == md_path:
            pdf_path = md_path + '.pdf'

    print(f'[INFO] Input:  {md_path}')
    print(f'[INFO] Output: {pdf_path}')

    success = convert_md_to_pdf(md_path, pdf_path)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
