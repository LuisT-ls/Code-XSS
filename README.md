# EthicScope XSS - Scanner Avançado de Vulnerabilidades

<p align="center">
  <img src="https://img.shields.io/badge/Segurança-Web-blue" alt="Web Security">
  <img src="https://img.shields.io/badge/Versão-2.0-green" alt="Version 2.0">
  <img src="https://img.shields.io/badge/Python-3.7+-yellow" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/Licença-MIT-red" alt="MIT License">
</p>

## 🔍 Descrição

EthicScope XSS é um scanner avançado para detecção e análise de vulnerabilidades Cross-Site Scripting (XSS) em aplicações web. Desenvolvido para profissionais de segurança e desenvolvedores, esta ferramenta realiza uma varredura completa em sites para identificar diferentes tipos de vulnerabilidades XSS, incluindo:

- XSS Refletido
- Potencial XSS baseado em DOM
- Análise de cabeçalhos de segurança
- Problemas em configuração de cookies
- Falhas em formulários web
- Vazamento de informações sensíveis em comentários

## ⚠️ Aviso de Uso Responsável

**ESTA FERRAMENTA DESTINA-SE EXCLUSIVAMENTE PARA FINS ÉTICOS E LEGAIS!**

- Você **DEVE** ter **AUTORIZAÇÃO EXPLÍCITA POR ESCRITO** do proprietário do sistema antes de realizar qualquer teste
- Realizar testes de penetração sem permissão é um crime em muitos países
- Use SOMENTE em sistemas que você possui ou para os quais tem permissão documentada
- O autor não se responsabiliza por qualquer uso indevido desta ferramenta

## ✨ Características Principais

- **Crawling Inteligente**: Navegação automática pelo site-alvo com controle de profundidade
- **Múltiplas Técnicas de Detecção**: Testes para diferentes vetores e contextos de XSS
- **Análise Detalhada de Segurança**: Verificação abrangente de configurações de segurança
- **Payloads Avançados**: Biblioteca extensível de payloads, incluindo técnicas de bypass de WAF
- **Análise de DOM**: Identificação de possíveis vulnerabilidades em JavaScript
- **Concorrência**: Uso de multithreading para escaneamento rápido e eficiente
- **Relatórios Detalhados**: Geração de relatórios completos em formatos TXT e JSON
- **Configurável**: Opções de personalização via arquivo .env e arquivos de payloads

## 🛠️ Requisitos

- Python 3.7 ou superior
- Bibliotecas:
  - requests
  - beautifulsoup4
  - colorama
  - python-dotenv
  - urllib3

## 📦 Instalação

```bash
# Clonar o repositório
git clone https://github.com/LuisT-ls/Code-XSS.git
cd Code-XSS

# Instalar dependências
pip install requests beautifulsoup4 colorama python-dotenv urllib3
```

Alternativamente, você pode criar um ambiente virtual:

```bash
# Criar e ativar ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instalar dependências
pip install requests beautifulsoup4 colorama python-dotenv urllib3
```

## 🚀 Uso

Para iniciar o scanner:

```bash
python xss.py
```

### Menu Interativo

O programa oferece um menu com várias opções:

1. **Iniciar escaneamento completo**: Realiza uma análise completa de um site-alvo
2. **Configurar opções avançadas**: Personaliza parâmetros de execução do scanner
3. **Verificar cabeçalhos de segurança**: Analisa apenas os cabeçalhos HTTP de segurança
4. **Sair**: Encerra o programa

### Escaneamento Completo

Ao selecionar a opção 1, você deve:

1. Informar a URL alvo (ex: `https://exemplo.com.br`)
2. Definir a profundidade de crawling (1-5, padrão: 2)
3. Estabelecer um número máximo de URLs a serem escaneadas (padrão: 100)

O scanner então iniciará o processo de:

- Crawling do site
- Análise de URLs e formulários
- Identificação de vulnerabilidades
- Geração de relatórios

## ⚙️ Configuração

### Arquivo .env

O scanner utiliza um arquivo `.env` para configurações avançadas:

```
MAX_WORKERS=10       # Número máximo de threads
TIMEOUT=15           # Timeout para requisições (segundos)
FOLLOW_REDIRECTS=True   # Seguir redirecionamentos
VERIFY_SSL=False     # Verificar certificados SSL
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
# PROXY=http://seu-proxy:porta  # Opcional: configure um proxy
```

### Personalização de Payloads

Você pode personalizar os payloads utilizados nos testes editando os arquivos:

- `xss_payloads.txt`: Payloads padrão para testes de XSS
- `bypass_payloads.txt`: Payloads especializados para bypass de WAF e filtros

## 📊 Relatórios

Os resultados são salvos em dois formatos:

### Relatório de Texto (vulnerability_report.txt)

Contém uma visão detalhada das vulnerabilidades encontradas, incluindo:

- Resumo estatístico
- Detalhes de cada vulnerabilidade
- Recomendações para correção
- Informações sobre o escaneamento

### Relatório JSON (vulnerability_report.json)

Formato estruturado para integração com outras ferramentas:

- Metadados de escaneamento
- Estatísticas completas
- Array de vulnerabilidades com detalhes

## 📋 Exemplos de Saída

### Vulnerabilidade XSS Refletido

```
🚨 VULNERABILIDADE DETECTADA!
Tipo: Reflected XSS
Severidade: Alta
URL: https://exemplo.com.br/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
Payload: <script>alert('XSS')</script>
Parameter: q
Evidence: Payload refletido na resposta
```

### Problema de Cabeçalho de Segurança

```
🚨 VULNERABILIDADE DETECTADA!
Tipo: Cabeçalho de Segurança Ausente
Severidade: Alta
URL: https://exemplo.com.br
Header: Content-Security-Policy
Message: Content Security Policy (CSP) não configurada
Description: A falta de CSP aumenta o risco de ataques XSS e de injeção de conteúdo
```

## 🔄 Workflow de Segurança

Para integrar esta ferramenta em seu workflow de segurança:

1. **Desenvolvimento**: Teste regularmente durante o ciclo de desenvolvimento
2. **Pré-produção**: Execute varreduras completas antes de deployments
3. **Produção**: Realize testes periódicos com escopo limitado e autorizado
4. **CI/CD**: Integre com seus pipelines de integração contínua

## 🛡️ Boas Práticas de Prevenção XSS

1. **Escapar saídas**: Sempre escape dados de usuário antes de renderizar em HTML
2. **Implementar CSP**: Configure uma Content Security Policy rigorosa
3. **Validar entradas**: Valide e sanitize todas as entradas de usuário
4. **Usar frameworks modernos**: Frameworks como React, Angular e Vue têm proteções embutidas
5. **Aplicar HttpOnly e Secure**: Configure cookies corretamente
6. **Implementar HSTS**: Force conexões HTTPS

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e enviar pull requests para melhorar esta ferramenta.

Para contribuir:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

## 📜 Licença

Este projeto está licenciado sob a [Licença MIT](LICENSE) - veja o arquivo LICENSE para detalhes.

## 📞 Contato

Para sugestões, feedback ou dúvidas, abra uma issue no GitHub.

---

<p align="center">
  <b>Use de forma ética e responsável!</b><br>
  Desenvolvido com ❤️ para a comunidade de segurança
</p>
