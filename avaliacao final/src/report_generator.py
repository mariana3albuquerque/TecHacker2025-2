import json, os, datetime

def save_json_report(data, outdir='reports'):
    os.makedirs(outdir, exist_ok=True)
    fname = f"report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(outdir, fname)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path

def save_markdown_report(data, outdir='reports'):
    os.makedirs(outdir, exist_ok=True)
    fname = f"report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
    path = os.path.join(outdir, fname)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"# Relatório de Segurança - {data.get('url')}\n\n")
        if data.get('vulnerabilities'):
            f.write('| Tipo | Detalhes |\n|---|---|\n')
            for v in data['vulnerabilities']:
                details = ', '.join(f"{k}: {v[k]}" for k in v if k != 'type')
                f.write(f"| {v.get('type')} | {details} |\n")
        else:
            f.write('Nenhuma vulnerabilidade identificada.\n')

        # incluir resultados de ferramentas externas
        if data.get('external_scans'):
            f.write('\n## External scans\n')
            for s in data['external_scans']:
                if s.get('stdout'):
                    summary = s['stdout'][:800] + '...' if len(s['stdout']) > 800 else s['stdout']
                    # bloco de código markdown com a saída resumida
                    f.write(f"- {s.get('type')}: saída (resumida) abaixo:\n")
                    f.write("```\n")
                    f.write(summary)
                    f.write("\n```\n")
                else:
                    f.write(f"- {s.get('type')}: {s.get('note', s.get('error', 'output not available'))}\n")
    return path
