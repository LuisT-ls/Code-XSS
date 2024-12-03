import requests
import re
import sys
import time
from urllib.parse import urljoin, urlparse
import concurrent.futures
import urllib3
import colorama
from colorama import Fore, Style
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os
import json

# Disable certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

# Responsible Use Disclaimer Function
def display_responsible_use_warning():
    print(f"\n{Fore.RED}🚨 AVISO IMPORTANTE DE USO RESPONSÁVEL 🚨{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Este scanner de vulnerabilidades destina-se APENAS a fins éticos e legais:{Style.RESET_ALL}")
    print("1. Você DEVE ter AUTORIZAÇÃO EXPLÍCITA por escrito do proprietário do sistema antes de realizar qualquer teste.")
    print("2. Realizar testes de penetração sem permissão é um crime em muitos países.")
    print("3. Este scanner deve ser usado APENAS em:")
    print("   - Sistemas que você possui")
    print("   - Sistemas para os quais tem permissão documentada")
    print("   - Ambientes de teste controlados")
    print(f"\n{Fore.RED}Uso não autorizado pode resultar em:{Style.RESET_ALL}")
    print("- Ações legais")
    print("- Processo criminal")
    print("- Multas significativas")
    
    consent = input(f"\n{Fore.CYAN}Você leu, entende e concorda com estes termos? (s/n): {Style.RESET_ALL}").strip().lower()
    
    if consent != 's':
        print(f"\n{Fore.RED}❌ Operação cancelada. Uso não autorizado não é permitido.{Style.RESET_ALL}")
        sys.exit(1)

class AdvancedVulnerabilityScanner:
    def __init__(self, base_url):
        colorama.init(autoreset=True)
        self.base_url = base_url
        self.found_vulnerabilities = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
        self.max_workers = int(os.getenv('MAX_WORKERS', 10))
        self.timeout = int(os.getenv('TIMEOUT', 10))

    def validate_url(self, url):
      try:
          result = urlparse(url)
          return all([result.scheme in ('http', 'https'), result.netloc])
      except Exception as e:
          print(f"Erro ao validar URL: {e}")
          return False

        
    def extract_links_and_forms(self, html_content):
        soup = BeautifulSoup(html_content, "html.parser")
        links = [urljoin(self.base_url, a.get('href')) for a in soup.find_all('a', href=True)]
        forms = soup.find_all('form')
        return links, forms
    
    def scan_xss_and_sqli(self):
        """Varredura para XSS e SQL Injection"""
        try:
            response = requests.get(self.base_url, headers=self.headers, verify=False, timeout=self.timeout)
            links, forms = self.extract_links_and_forms(response.text)
            print(f"Links encontrados: {len(links)} | Formulários encontrados: {len(forms)}")
            
            payloads_xss = [
                "<script>alert('XSS')</script>",
                "'><img src=x onerror=alert(1)>",
            ]
            payloads_sqli = ["' OR '1'='1", "' UNION SELECT NULL, NULL --"]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                
                # Testar links com payloads XSS e SQLi
                for link in links:
                    for payload in payloads_xss + payloads_sqli:
                        futures.append(executor.submit(self._test_payload_on_link, link, payload))
                
                # Testar formulários
                for form in forms:
                    for payload in payloads_xss + payloads_sqli:
                        futures.append(executor.submit(self._test_form_submission, form, payload))
                
                concurrent.futures.wait(futures)

        except Exception as e:
            print(f"Erro na varredura: {e}")

    def extract_forms(self, html_content):
        """Extrair formulários da página."""
        form_pattern = re.compile(r'<form.*?>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input.*?>', re.IGNORECASE)
        
        forms = form_pattern.findall(html_content)
        form_details = []

        for form in forms:
            inputs = input_pattern.findall(form)
            method_match = re.search(r'method=[\'"]?(get|post)[\'"]?', form, re.IGNORECASE)
            action_match = re.search(r'action=[\'"]?([^\'" >]+)', form)

            form_info = {
                'method': method_match.group(1) if method_match else 'GET',
                'action': action_match.group(1) if action_match else self.base_url,
                'inputs': inputs
            }
            form_details.append(form_info)

        return form_details

    def generate_report_json(self):
        """Gera um relatório de vulnerabilidades em formato JSON."""
        with open('vulnerability_report.json', 'w') as f:
            json.dump(self.found_vulnerabilities, f, indent=4)
        print(f"{Fore.GREEN}✅ Relatório JSON salvo em vulnerability_report.json{Style.RESET_ALL}")


    def scan_xss_comprehensive(self):
        try:
            print(f"\n{Fore.CYAN}🔍 Iniciando varredura avançada de XSS em: {self.base_url}{Style.RESET_ALL}")
            
            # Obter página inicial
            initial_response = requests.get(
                self.base_url, 
                headers=self.headers, 
                verify=False, 
                timeout=10
            )
            
            # Extrair formulários
            forms = self.extract_forms(initial_response.text)
            print(f"{Fore.YELLOW}📋 Formulários encontrados: {len(forms)}{Style.RESET_ALL}")

            # Payloads mais avançados
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "'\"><script>alert(document.cookie)</script>",
                "<svg/onload=alert('XSS')>",
                "javascript&#58;alert('XSS')",
                "&#x6A;avascript:alert('XSS')",
                "<iframe src='javascript:alert(`XSS`)'>",
                "\" onfocus=alert('XSS') autofocus>",
            ]

            # Varredura concorrente
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                
                # Varredura de parâmetros GET
                for payload in xss_payloads:
                    future = executor.submit(
                        self._test_get_parameters, 
                        payload
                    )
                    futures.append(future)
                
                # Varredura de formulários
                for form in forms:
                    for payload in xss_payloads:
                        future = executor.submit(
                            self._test_form_inputs, 
                            form, 
                            payload
                        )
                        futures.append(future)
                
                # Aguardar resultados
                concurrent.futures.wait(futures)

        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}❌ Erro na varredura: {e}{Style.RESET_ALL}")

    def _test_payload_on_link(self, link, payload):
        """Testar payload em links"""
        try:
            test_url = f"{link}?test={payload}"
            response = requests.get(test_url, headers=self.headers, verify=False, timeout=self.timeout)
            if payload in response.text:
                self._report_vulnerability("XSS/SQLi in URL", link, payload)
        except Exception as e:
            print(f"Erro ao testar link {link}: {e}")

    def _test_form_submission(self, form, payload):
        """Testar submissão de formulários"""
        try:
            action = form.get('action') or self.base_url
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_data = {inp.get('name'): payload for inp in inputs if inp.get('name')}

            if method == 'post':
                response = requests.post(urljoin(self.base_url, action), data=form_data, headers=self.headers, verify=False, timeout=self.timeout)
            else:
                response = requests.get(urljoin(self.base_url, action), params=form_data, headers=self.headers, verify=False, timeout=self.timeout)
            
            if payload in response.text:
                self._report_vulnerability("XSS/SQLi in Form", action, payload)
        except Exception as e:
            print(f"Erro ao testar formulário: {e}")

    def _test_get_parameters(self, payload):
        """Testar parâmetros GET"""
        try:
            params = {'q': payload, 'search': payload, 'id': payload}
            
            for key, value in params.items():
                full_url = f"{self.base_url}?{key}={value}"
                response = requests.get(
                    full_url, 
                    headers=self.headers, 
                    verify=False, 
                    timeout=10
                )
                
                if payload in response.text:
                    vulnerability = {
                        'type': 'Reflected XSS',
                        'payload': payload,
                        'parameter': key,
                        'url': full_url,
                        'method': 'GET'
                    }
                    
                    self._report_vulnerability(vulnerability)
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ Erro em teste GET: {e}{Style.RESET_ALL}")

    def _test_form_inputs(self, form, payload):
        """Testar inputs de formulários"""
        try:
            method = form['method'].group(1).upper() if form['method'] else 'GET'
            action = form['action'].group(1) if form['action'] else self.base_url

            # Simular submissão de formulário
            form_data = {}
            for input_tag in form['inputs']:
                name_match = re.search(r'name=[\'"]?([^\'" >]+)', input_tag)
                if name_match:
                    form_data[name_match.group(1)] = payload

            response = requests.request(
                method, 
                action, 
                data=form_data,
                headers=self.headers,
                verify=False,
                timeout=10
            )

            if payload in response.text:
                vulnerability = {
                    'type': 'Potential Form-based XSS',
                    'payload': payload,
                    'method': method,
                    'action': action,
                    'inputs': list(form_data.keys())
                }
                
                self._report_vulnerability(vulnerability)
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ Erro em teste de formulário: {e}{Style.RESET_ALL}")

    def analyze_headers(self):
        """Analisar cabeçalhos HTTP de segurança"""
        response = requests.get(self.base_url, headers=self.headers, verify=False, timeout=self.timeout)
        headers = response.headers
        issues = []
        if 'X-Content-Type-Options' not in headers:
            issues.append("Falta o cabeçalho X-Content-Type-Options")
        if 'Content-Security-Policy' not in headers:
            issues.append("Falta o cabeçalho Content-Security-Policy")
        if 'Strict-Transport-Security' not in headers:
            issues.append("Falta o cabeçalho HSTS")
        for issue in issues:
            self._report_vulnerability("Security Header Issue", self.base_url, issue)

    def _report_vulnerability(self, vulnerability):
        """Método sincronizado para adicionar vulnerabilidade"""
        self.found_vulnerabilities.append(vulnerability)
        
        print(f"\n{Fore.RED}🚨 VULNERABILIDADE DETECTADA! {Style.RESET_ALL}")
        for key, value in vulnerability.items():
            print(f"{Fore.GREEN}{key.capitalize()}:{Style.RESET_ALL} {value}")

    def generate_report(self):
        print(f"\n{Fore.CYAN}📋 Relatório Final de Vulnerabilidades{Style.RESET_ALL}")
        
        if self.found_vulnerabilities:
            print(f"{Fore.RED}🚨 FORAM ENCONTRADAS {len(self.found_vulnerabilities)} VULNERABILIDADES!{Style.RESET_ALL}")
            
            # Salvar relatório em arquivo
            with open('vulnerability_report.txt', 'w') as f:
                f.write("Relatório de Vulnerabilidades XSS\n")
                f.write("===================================\n\n")
                for index, vuln in enumerate(self.found_vulnerabilities, 1):
                    f.write(f"Vulnerabilidade #{index}\n")
                    for key, value in vuln.items():
                        f.write(f"{key.capitalize()}: {value}\n")
                    f.write("\n")
            
            print(f"{Fore.GREEN}✅ Relatório salvo em vulnerability_report.txt{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ Nenhuma vulnerabilidade crítica encontrada{Style.RESET_ALL}")

    def generate_report_json(self):
      with open('vulnerability_report.json', 'w') as f:
          json.dump(self.found_vulnerabilities, f, indent=4)
      print(f"{Fore.GREEN}✅ Relatório JSON salvo em vulnerability_report.json{Style.RESET_ALL}")


def main():
    # Display responsible use warning BEFORE any scanning begins
    display_responsible_use_warning()
    
    print(f"{Fore.CYAN}🔒 Scanner Avançado de Vulnerabilidades XSS{Style.RESET_ALL}")
    
    while True:
        url = input("\nDigite a URL para escanear (ou 'sair' para encerrar): ").strip()
        
        if url.lower() == 'sair':
            break
        
        scanner = AdvancedVulnerabilityScanner(url)
        
        if not scanner.validate_url(url):
            print(f"{Fore.RED}❌ URL inválida. Tente novamente.{Style.RESET_ALL}")
            continue
        
        try:
            start_time = time.time()
            scanner.scan_xss_comprehensive()
            scanner.generate_report()
            scanner.generate_report_json()
            end_time = time.time()
            
            print(f"\n⏱️ Tempo de varredura: {end_time - start_time:.2f} segundos")
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️ Varredura interrompida pelo usuário.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Erro inesperado: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperação cancelada.")
        sys.exit(0)
        