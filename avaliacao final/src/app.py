from flask import Flask, request, render_template_string, Markup
from scanner import run_scan
from report_generator import save_json_report, save_markdown_report
import os
import markdown

app = Flask(__name__)

TEMPLATE = '''<!doctype html>
<title>Scanner - Conceito B</title>
<h1>Scanner Conceito B</h1>
<form method="post">
  URL: <input type="text" name="url" size="60" placeholder="https://example.com"><br><br>
  <input type="checkbox" name="use_nmap"> Use Nmap<br>
  <input type="checkbox" name="use_nikto"> Use Nikto<br><br>
  <input type="submit" value="Scan">
</form>
{% if md_html %}
<hr>
<h2>Relatório (renderizado)</h2>
<div>{{ md_html|safe }}</div>
<hr>
<p>Arquivos salvos em: <strong>{{ json_path }}</strong> e <strong>{{ md_path }}</strong></p>
{% elif report %}
<hr>
<h2>Resultado (texto)</h2>
<pre>{{ report }}</pre>
{% endif %}
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    report = None
    json_path = md_path = None
    md_html = None
    if request.method == 'POST':
        url = request.form.get('url')
        use_nmap = True if request.form.get('use_nmap') else False
        use_nikto = True if request.form.get('use_nikto') else False
        if url:
            # run scan (not dry-run by default)
            result = run_scan(url, dry_run=False, use_nmap=use_nmap, use_nikto=use_nikto)
            json_path = save_json_report(result)
            md_path = save_markdown_report(result)
            report = result
            # read md and convert to HTML
            try:
                with open(md_path, 'r', encoding='utf-8') as f:
                    md_text = f.read()
                md_html = Markup(markdown.markdown(md_text, extensions=['fenced_code', 'codehilite']))
            except Exception as e:
                md_html = Markup(f"<pre>Erro ao renderizar markdown: {e}</pre>")
    return render_template_string(TEMPLATE, report=report, json_path=json_path, md_path=md_path, md_html=md_html)

if __name__ == '__main__':
    os.makedirs('reports', exist_ok=True)
    app.run(host='0.0.0.0', port=5000)
