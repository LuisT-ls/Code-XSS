# Scanner Avançado de Vulnerabilidades XSS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Um scanner de vulnerabilidades XSS (Cross-Site Scripting) e SQL Injection robusto e eficiente, desenvolvido em Python. Esta ferramenta foi projetada para auxiliar profissionais de segurança e desenvolvedores na identificação de possíveis vulnerabilidades em aplicações web.

## ⚠️ Aviso de Uso Responsável

Este scanner destina-se APENAS a fins éticos e legais. Antes de utilizar esta ferramenta, certifique-se de que você:

- Possui AUTORIZAÇÃO EXPLÍCITA por escrito do proprietário do sistema
- Está testando apenas sistemas que você possui ou tem permissão documentada
- Está utilizando em ambientes de teste controlados

O uso não autorizado desta ferramenta pode resultar em:

- Ações legais
- Processo criminal
- Multas significativas

## 📋 Requisitos

- Python 3.x
- python3-venv (para criação do ambiente virtual)
- Bibliotecas Python listadas em `requirements.txt`

## 🛠️ Instalação

1. Clone o repositório:

```bash
git clone https://github.com/LuisT-ls/Code-XSS.git
cd Code-XSS
```

2. Instale o pacote python3-venv (necessário para ambientes virtuais):

```bash
sudo apt install python3-venv python3-full
```

3. Crie um ambiente virtual:

```bash
python3 -m venv venv
```

4. Ative o ambiente virtual:

```bash
source venv/bin/activate
```

5. Instale as dependências:

```bash
pip install requests beautifulsoup4 colorama python-dotenv urllib3
```

6. (Opcional) Para gerar um arquivo de requisitos:

```bash
pip freeze > requirements.txt
```

**Nota**: Para desativar o ambiente virtual quando terminar, use:

```bash
deactivate
```

## 💻 Uso

Com o ambiente virtual ativado, execute o scanner através do comando:

```bash
python xss.py
```

O programa irá:

1. Exibir o aviso de uso responsável
2. Solicitar a URL alvo
3. Realizar a varredura completa
4. Gerar relatórios em TXT e JSON

## 📊 Relatórios

O scanner gera dois tipos de relatórios:

- `vulnerability_report.txt`: Relatório detalhado em formato texto
- `vulnerability_report.json`: Relatório estruturado em formato JSON

## 🔧 Configuração

As seguintes variáveis podem ser configuradas através de um arquivo `.env`:

- `MAX_WORKERS`: Número máximo de workers para execução paralela (padrão: 10)
- `TIMEOUT`: Tempo limite para requisições em segundos (padrão: 10)

## 📁 Estrutura do Projeto

```
.
├── LICENSE
├── README.md
├── vulnerability_report.json
├── vulnerability_report.txt
└── xss.py
```

## 🤝 Contribuição

Contribuições são bem-vindas! Por favor, sinta-se à vontade para enviar pull requests ou abrir issues para melhorias.

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🔒 Segurança

Para reportar vulnerabilidades de segurança, por favor, abra uma issue descrevendo o problema encontrado.

## ⚡ Limitações

- O scanner não garante a detecção de todas as vulnerabilidades possíveis
- Falsos positivos podem ocorrer
- O uso em sites com alta carga pode causar impacto no desempenho

---

**Nota**: Este é um projeto em desenvolvimento. Use com responsabilidade e sempre priorize a segurança e a ética em testes de penetração.
