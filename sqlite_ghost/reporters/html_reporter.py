import os
from jinja2 import Environment, BaseLoader

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SQLite-Ghost Forensic Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #0f172a; color: #cbd5e1; }
        .container { max-width: 1100px; margin: 40px auto; background: #1e293b; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        h1, h2, h3 { color: #f8fafc; border-bottom: 1px solid #334155; padding-bottom: 10px; }
        
        .threat-level { font-size: 24px; font-weight: bold; padding: 8px 15px; border-radius: 5px; display: inline-block; margin-bottom: 20px;}
        .threat-CRITICAL { background-color: #ef4444; color: white; }
        .threat-HIGH { background-color: #f97316; color: white; }
        .threat-MEDIUM { background-color: #eab308; color: black; }
        .threat-LOW { background-color: #3b82f6; color: white; }
        .threat-CLEAN { background-color: #22c55e; color: white; }
        
        table { width: 100%; border-collapse: collapse; margin-top: 15px; background-color: #0f172a; }
        th, td { padding: 12px; text-align: left; border: 1px solid #334155; }
        th { background-color: #1e293b; color: #f8fafc; }
        
        .badge { font-weight: bold; padding: 4px 8px; border-radius: 4px; font-size: 12px; display: inline-block; }
        .badge-CRITICAL { background-color: #ef4444; color: white; }
        .badge-HIGH { background-color: #f97316; color: white; }
        .badge-MEDIUM { background-color: #eab308; color: black; }
        .badge-LOW { background-color: #3b82f6; color: white; }
        
        .pre-wrap { white-space: pre-wrap; font-family: 'Courier New', Courier, monospace; background: #000; padding: 10px; border-radius: 5px; font-size: 13px; color: #a5b4fc; }
        
        .section { margin-bottom: 40px; }
        .toggle-btn { background-color: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-top: 10px; font-weight: bold; }
        .toggle-btn:hover { background-color: #2563eb; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SQLite-Ghost Forensic Analysis</h1>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p><strong>Target Database:</strong> {{ db_path }}</p>
            <p><strong>Page Size:</strong> {{ page_size }} bytes</p>
            <p><strong>Total Orphaned Records Carved:</strong> {{ slack_records }}</p>
            <p><strong>Overall Threat Level:</strong> <span class="threat-level threat-{{ anomaly_score }}">{{ anomaly_score }}</span></p>
        </div>
        
        <div class="section">
            <h2>Section 1 &mdash; Suspicious Hits</h2>
            <p>Triage markers matched against carved payloads in unallocated space and WAL segments.</p>
            {% if suspicious_hits %}
            <table>
                <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Source (Offset)</th>
                    <th>Matched Markers</th>
                    <th>Confidence</th>
                    <th>Recovered Payload</th>
                </tr>
                {% for hit in suspicious_hits %}
                <tr class="hit-row" {% if loop.index > 5 %}style="display: none;"{% endif %}>
                    <td>{{ hit.get('timestamp', 'Unknown') }}</td>
                    <td>{{ hit.source }}<br><small>{% if hit.offset is number %}0x{{ "%04X"|format(hit.offset) }}{% else %}{{ hit.offset }}{% endif %}</small></td>
                    <td>{{ hit.markers | join(', ') }}</td>
                    <td><span class="badge badge-{{ hit.confidence }}">{{ hit.confidence }}</span></td>
                    <td>{{ hit.payload }}</td>
                </tr>
                {% endfor %}
            </table>
            {% if suspicious_hits|length > 5 %}
            <button onclick="toggleRows('hit-row', this)" class="toggle-btn">See More ({{ suspicious_hits|length - 5 }} hidden)</button>
            {% endif %}
            {% else %}
            <p>No suspicious triage markers matched.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Section 2 &mdash; Anomaly & Tampering Log</h2>
            <p>Structural anomalies, header manipulations, and tampering evidence.</p>
            {% if anomalies %}
            <table>
                <tr>
                    <th width="15%">Severity</th>
                    <th>Description</th>
                </tr>
                {% for anomaly in anomalies %}
                <tr class="anomaly-row" {% if loop.index > 5 %}style="display: none;"{% endif %}>
                    <td><span class="badge badge-{{ anomaly.severity }}">{{ anomaly.severity }}</span></td>
                    <td>{{ anomaly.desc }}</td>
                </tr>
                {% endfor %}
            </table>
            {% if suspicious_hits|length > 5 %}
            <button onclick="toggleRows('hit-row', this)" class="toggle-btn">See More ({{ suspicious_hits|length - 5 }} hidden)</button>
            {% endif %}
            {% else %}
            <p>No structural anomalies detected.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Appendices &mdash; Forensic Integrity & Hex Excerpts</h2>
            
            <h3>Acquisition Metadata (Chain of Custody)</h3>
            <p>Files securely duplicated and analyzed offline.</p>
            <table>
                <tr>
                    <th>Target</th>
                    <th>Path</th>
                    <th>MD5</th>
                    <th>SHA-256</th>
                </tr>
                <tr>
                    <td>Primary Database</td>
                    <td>{{ acquisition.db_original }}</td>
                    <td><small>{{ acquisition.db_hashes.md5 }}</small></td>
                    <td><small>{{ acquisition.db_hashes.sha256 }}</small></td>
                </tr>
                {% if acquisition.wal_original %}
                <tr>
                    <td>Write-Ahead Log</td>
                    <td>{{ acquisition.wal_original }}</td>
                    <td><small>{{ acquisition.wal_hashes.md5 }}</small></td>
                    <td><small>{{ acquisition.wal_hashes.sha256 }}</small></td>
                </tr>
                {% endif %}
            </table>
            
            <h3>Binary Excerpts for Suspicious Hits</h3>
            {% if suspicious_hits %}
                {% for hit in suspicious_hits %}
                <div class="excerpt-row" {% if loop.index > 5 %}style="display: none;"{% endif %}>
                <p><strong>Hit {{ loop.index }} ({{ hit.source }} @ {% if hit.offset is number %}0x{{ "%04X"|format(hit.offset) }}{% else %}{{ hit.offset }}{% endif %}):</strong></p>
                <div class="pre-wrap">{{ hit.hex_dump }}</div>
                </div>
                {% endfor %}
            {% if suspicious_hits|length > 5 %}
            <button onclick="toggleRows('excerpt-row', this)" class="toggle-btn">See More ({{ suspicious_hits|length - 5 }} hidden)</button>
            {% endif %}
            {% else %}
                <p>No hits to generate excerpts for.</p>
            {% endif %}
        </div>
    </div>
    <script>
        function toggleRows(className, btn) {
            var rows = document.getElementsByClassName(className);
            var isHidden = false;
            for (var i = 0; i < rows.length; i++) {
                if (rows[i].style.display === 'none') {
                    isHidden = true;
                    break;
                }
            }
            for (var i = 5; i < rows.length; i++) {
                if (rows[i].tagName === 'TR') {
                    rows[i].style.display = isHidden ? 'table-row' : 'none';
                } else {
                    rows[i].style.display = isHidden ? 'block' : 'none';
                }
            }
            if (isHidden) {
                btn.innerHTML = 'Show Less';
            } else {
                btn.innerHTML = 'See More (' + (rows.length - 5) + ' hidden)';
            }
        }
    </script>
</body>
</html>
"""

def generate_html(data: dict, output_path: str):
    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)
    html_content = template.render(**data)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
