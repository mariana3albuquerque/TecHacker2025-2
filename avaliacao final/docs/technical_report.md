# Relatório Técnico — Projeto Conceito B

## Visão Geral
Este documento descreve a arquitetura, metodologia de testes, ferramentas utilizadas, critérios de avaliação e instruções para reprodução do projeto "Conceito B" — Ferramenta de Avaliação de Segurança de Aplicações Web.

O projeto implementa uma ferramenta capaz de realizar varreduras automatizadas básicas em aplicações web, detectar vulnerabilidades comuns (XSS, SQLi heurístico, Directory Traversal, exposição de dados sensíveis) e integrar ferramentas auxiliares como Nmap e Nikto.

## Arquitetura
- **Frontend web (Flask):** interface simples para envio de URLs, habilitação de Nmap/Nikto, e visualização do relatório em Markdown renderizado.
- **Scanner (scanner.py):** scripts próprios em Python para heurísticas rápidas + integrações com ferramentas externas (Nmap/Nikto).
- **Gerador de relatórios (report_generator.py):** gera relatórios em JSON e Markdown, armazenados em `/reports`.
- **Relatórios no site:** o arquivo Markdown gerado é lido e renderizado pelo Flask, disponibilizando o relatório no navegador imediatamente após a varredura.

## Ferramentas utilizadas
- Linguagem: Python 3.11
- Framework web: Flask
- Bibliotecas Python: requests, markdown
- Ferramentas auxiliares (opcionais): Nmap, Nikto

## Metodologia de Testes
1. **Definição do alvo** — utilizar apenas alvos autorizados (localhost, ambientes de teste, Juice Shop).
2. **Execução automatizada** — o scanner executa uma série de heurísticas e, opcionalmente, Nmap/Nikto.
3. **Geração de relatórios** — resultados salvos em JSON e Markdown; Markdown é renderizado na interface.
4. **Validação manual** — revisar evidências e reduzir falsos positivos manualmente.

## Estrutura de diretórios
```
/src
  scanner.py
  report_generator.py
  app.py
  zap_client.py
  requirements.txt
/docs
  technical_report.md
/reports
  report_YYYYMMDD_HHMMSS.json
  report_YYYYMMDD_HHMMSS.md
```

## Como reproduzir (exemplo)
1. Criar virtualenv:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt
```
2. Rodar o servidor:
```bash
python src/app.py
```
3. Acessar `http://localhost:5000`, inserir a URL alvo e clicar em **Scan**.
4. O relatório renderizado aparecerá na página e os arquivos serão salvos em `/reports`.

## Considerações de Segurança e Ética
- Realizar varreduras apenas em alvos com autorização documentada.
- Evitar varreduras agressivas em ambientes de produção.
- Manter logs e evidências para auditoria.

## Sugestões de melhorias
- Autenticação e autorização para uso do serviço.
- Dashboard interativo com gráficos (Dash/Grafana).
- Priorização automática de vulnerabilidades por severidade.
- Integração com sistemas de ticketing para fluxo de correção.

