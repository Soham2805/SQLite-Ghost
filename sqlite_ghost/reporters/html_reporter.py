import os
from jinja2 import Environment, BaseLoader

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SQLite-Ghost Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; color: #333; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; }
        .threat-level { font-size: 28px; font-weight: bold; padding: 5px 10px; border-radius: 4px; display: inline-block; }
        .threat-CRITICAL { background-color: #e74c3c; color: white; }
        .threat-HIGH { background-color: #e67e22; color: white; }
        .threat-MEDIUM { background-color: #f1c40f; color: black; }
        .threat-LOW { background-color: #3498db; color: white; }
        .threat-CLEAN { background-color: #2ecc71; color: white; }
        .list { margin-top: 20px; list-style-type: none; padding: 0; }
        .list li { margin-bottom: 10px; padding: 10px; background-color: #fff; border-left: 5px solid #ccc; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .badge { font-weight: bold; padding: 3px 8px; border-radius: 3px; font-size: 12px; margin-right: 10px; }
        .badge-CRITICAL { background-color: #e74c3c; color: white; }
        .badge-HIGH { background-color: #e67e22; color: white; }
        .badge-MEDIUM { background-color: #f1c40f; color: black; }
        .badge-LOW { background-color: #3498db; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SQLite-Ghost Forensic Report</h1>
        <p><strong>Database:</strong> {{ db_path }}</p>
        <p><strong>Page Size:</strong> {{ page_size }} bytes</p>
        
        <h2>Overall Threat Level</h2>
        <div class="threat-level threat-{{ anomaly_score }}">{{ anomaly_score }}</div>
        
        <h2>Anomalies Detected</h2>
        <ul class="list">
            {% for anomaly in anomalies %}
                <li><span class="badge badge-{{ anomaly.severity }}">{{ anomaly.severity }}</span> {{ anomaly.desc }}</li>
            {% else %}
                <li>No anomalies detected.</li>
            {% endfor %}
        </ul>
        
        <h2>Carved Data</h2>
        <p>Found <strong>{{ slack_records }}</strong> orphaned records in slack space.</p>
    </div>
</body>
</html>
"""

def generate_html(data: dict, output_path: str):
    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)
    html_content = template.render(**data)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
