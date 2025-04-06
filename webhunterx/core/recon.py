#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import json
import time
import concurrent.futures
import sys
import os
import socket
import ssl
import subprocess
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Import des modules utilitaires
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webhunterx.utils import logger, http_tools

# Configuration globale
COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Dictionnaire des signatures de technologies web
TECH_SIGNATURES = {
    # Frameworks web
    "Laravel": [
        {"type": "header", "name": "Set-Cookie", "regex": r"laravel_session"},
        {"type": "content", "regex": r'content="Laravel'},
    ],
    "Django": [
        {"type": "header", "name": "Set-Cookie", "regex": r"csrftoken"},
        {"type": "content", "regex": r'name="csrfmiddlewaretoken"'},
    ],
    "Flask": [
        {"type": "header", "name": "Set-Cookie", "regex": r"session=.+?\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"},
    ],
    "ASP.NET": [
        {"type": "header", "name": "X-AspNet-Version", "regex": r".+"},
        {"type": "header", "name": "Set-Cookie", "regex": r"ASP\.NET_SessionId"},
        {"type": "content", "regex": r'__VIEWSTATE'},
    ],
    "Express.js": [
        {"type": "header", "name": "X-Powered-By", "regex": r"Express"},
    ],
    "Angular": [
        {"type": "content", "regex": r'ng-app|ng-controller|angular\.js|angular\.min\.js'},
    ],
    "React": [
        {"type": "content", "regex": r'react\.js|react\.min\.js|react-dom'},
        {"type": "content", "regex": r'_reactRootContainer'},
    ],
    "Vue.js": [
        {"type": "content", "regex": r'vue\.js|vue\.min\.js'},
        {"type": "content", "regex": r'data-v-|v-bind:|v-on:|v-if'},
    ],
    
    # Serveurs web
    "Apache": [
        {"type": "header", "name": "Server", "regex": r"Apache(?:/[0-9\.]+)?"},
    ],
    "Nginx": [
        {"type": "header", "name": "Server", "regex": r"nginx(?:/[0-9\.]+)?"},
    ],
    "Microsoft-IIS": [
        {"type": "header", "name": "Server", "regex": r"Microsoft-IIS(?:/[0-9\.]+)?"},
    ],
    
    # Base de données
    "MySQL": [
        {"type": "error", "regex": r"MySQL"},
        {"type": "error", "regex": r"SQL syntax.*MySQL"},
        {"type": "error", "regex": r"Warning.*mysql_.*"},
    ],
    "PostgreSQL": [
        {"type": "error", "regex": r"PostgreSQL.*ERROR"},
        {"type": "error", "regex": r"Warning.*\Wpg_.*"},
    ],
    "SQLite": [
        {"type": "error", "regex": r"SQLite/JDBCDriver"},
        {"type": "error", "regex": r"SQLite\.Exception"},
    ],
    "Oracle": [
        {"type": "error", "regex": r"ORA-[0-9]+"},
    ],
    
    # CMS
    "WordPress": [
        {"type": "header", "name": "Set-Cookie", "regex": r"wordpress_|wp-settings-"},
        {"type": "content", "regex": r'wp-content|wp-includes'},
        {"type": "generator", "regex": r'WordPress'},
    ],
    "Joomla": [
        {"type": "header", "name": "Set-Cookie", "regex": r"joomla_"},
        {"type": "content", "regex": r'com_content|com_contact|com_mailto'},
        {"type": "generator", "regex": r'Joomla'},
    ],
    "Drupal": [
        {"type": "header", "name": "X-Generator", "regex": r"Drupal"},
        {"type": "header", "name": "Set-Cookie", "regex": r"SESS[a-f0-9]{32}"},
        {"type": "content", "regex": r'Drupal\.settings|drupal\.js'},
        {"type": "generator", "regex": r'Drupal'},
    ],
    
    # Langages de programmation
    "PHP": [
        {"type": "header", "name": "X-Powered-By", "regex": r"PHP(?:/[0-9\.]+)?"},
        {"type": "header", "name": "Set-Cookie", "regex": r"PHPSESSID"},
    ],
    "Ruby": [
        {"type": "header", "name": "Server", "regex": r"Puma|WEBrick|Unicorn|Passenger"},
        {"type": "header", "name": "Set-Cookie", "regex": r"_session_id"},
    ],
    "Python": [
        {"type": "header", "name": "Server", "regex": r"gunicorn|Werkzeug"},
    ],
    
    # WAFs
    "Cloudflare": [
        {"type": "header", "name": "Server", "regex": r"cloudflare"},
        {"type": "header", "name": "CF-RAY", "regex": r".+"},
    ],
    "AWS WAF": [
        {"type": "header", "name": "X-AMZ-CF-ID", "regex": r".+"},
    ],
    "ModSecurity": [
        {"type": "header", "name": "Server", "regex": r"mod_security|NOYB"},
    ],
}

class Recon:
    def __init__(self, target, threads=5, stealth=False):
        self.target = target
        self.threads = threads
        self.stealth = stealth
        self.parsed_url = urlparse(target)
        self.domain = self.parsed_url.netloc
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.results = {
            "technologies": [],
            "subdomains": [],
            "open_ports": [],
            "endpoints": [],
            "headers": {},
            "ssl_info": {},
            "ip_addresses": []
        }
        self.log = logger.get_logger()
        
        # Ajustements pour le mode furtif
        if self.stealth:
            self.log.info("Mode furtif activé - Utilisation de délais entre les requêtes et rotation des User-Agents")
            http_tools.set_stealth_mode(True)
            
    def run_full_recon(self):
        """Lance la reconnaissance complète"""
        self.log.info(f"Début de la reconnaissance pour {self.target}")
        
        # Récupérer les informations de base
        self.get_target_info()
        
        # Scanner les ports ouverts
        self.scan_common_ports()
        
        # Identifier les technologies utilisées
        self.identify_technologies()
        
        # Découvrir les sous-domaines
        self.discover_subdomains()
        
        # Analyser le contenu JavaScript
        self.analyze_javascript()
        
        # Analyser la structure du site
        self.analyze_site_structure()
        
        return self.results
    
    def get_target_info(self):
        """Récupère les informations de base sur la cible"""
        try:
            self.log.info(f"Récupération des informations de base pour {self.domain}")
            response = http_tools.send_request(self.target)
            
            # Enregistrer les headers
            self.results["headers"] = dict(response.headers)
            
            # Récupérer les adresses IP
            try:
                ip_addresses = socket.gethostbyname_ex(self.domain)[2]
                self.results["ip_addresses"] = ip_addresses
                self.log.info(f"Adresses IP trouvées: {', '.join(ip_addresses)}")
            except socket.gaierror:
                self.log.warning(f"Impossible de résoudre l'adresse IP pour {self.domain}")
            
            # Récupérer les informations SSL si HTTPS
            if self.parsed_url.scheme == "https":
                self.get_ssl_info()
                
        except Exception as e:
            self.log.error(f"Erreur lors de la récupération des informations de base: {str(e)}")
            
    def get_ssl_info(self):
        """Récupère les informations sur le certificat SSL"""
        try:
            self.log.info(f"Récupération des informations SSL pour {self.domain}")
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extraire les informations importantes
                    ssl_info = {
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "subject": dict(x[0] for x in cert["subject"]),
                        "version": cert["version"],
                        "not_before": cert["notBefore"],
                        "not_after": cert["notAfter"],
                    }
                    
                    # Ajouter les noms alternatifs du sujet
                    if "subjectAltName" in cert:
                        alt_names = [x[1] for x in cert["subjectAltName"] if x[0].lower() == "dns"]
                        ssl_info["alt_names"] = alt_names
                        
                        # Ajouter ces noms comme sous-domaines potentiels
                        for name in alt_names:
                            if name not in self.results["subdomains"] and name != self.domain:
                                self.results["subdomains"].append(name)
                    
                    self.results["ssl_info"] = ssl_info
                    self.log.info(f"Informations SSL récupérées pour {self.domain}")
        except Exception as e:
            self.log.error(f"Erreur lors de la récupération des informations SSL: {str(e)}")
            
    def scan_common_ports(self):
        """Scanne les ports courants pour les services web"""
        self.log.info(f"Scan des ports courants pour {self.domain}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_port, port): port for port in COMMON_PORTS}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        self.results["open_ports"].append(port)
                        self.log.info(f"Port {port} ouvert sur {self.domain}")
                        
                        # Tenter de récupérer la bannière du serveur
                        self._get_server_banner(port)
                except Exception as e:
                    self.log.error(f"Erreur lors du scan du port {port}: {str(e)}")
        
        self.log.info(f"Ports ouverts: {', '.join(map(str, self.results['open_ports']))}")
        
    def _check_port(self, port):
        """Vérifie si un port est ouvert"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.domain, port))
        sock.close()
        return result == 0
    
    def _get_server_banner(self, port):
        """Tente de récupérer la bannière du serveur web"""
        scheme = "https" if port == 443 else "http"
        try:
            url = f"{scheme}://{self.domain}:{port}"
            response = http_tools.send_request(url)
            if "Server" in response.headers:
                self.log.info(f"Serveur sur le port {port}: {response.headers['Server']}")
        except:
            pass
            
    def identify_technologies(self):
        """Identifie les technologies utilisées par la cible"""
        self.log.info(f"Identification des technologies utilisées par {self.target}")
        
        try:
            response = http_tools.send_request(self.target)
            content = response.text
            headers = response.headers
            
            # Chercher les technologies basées sur les signatures
            for tech_name, signatures in TECH_SIGNATURES.items():
                found = False
                for signature in signatures:
                    if signature["type"] == "header" and "name" in signature:
                        if signature["name"] in headers:
                            if re.search(signature["regex"], headers[signature["name"]], re.I):
                                found = True
                                break
                    elif signature["type"] == "content":
                        if re.search(signature["regex"], content, re.I):
                            found = True
                            break
                    elif signature["type"] == "generator":
                        # Chercher la balise meta generator
                        soup = BeautifulSoup(content, 'html.parser')
                        generator = soup.find("meta", {"name": "generator"})
                        if generator and generator.get("content"):
                            if re.search(signature["regex"], generator["content"], re.I):
                                found = True
                                break
                    elif signature["type"] == "error":
                        # Chercher les messages d'erreur potentiels
                        if re.search(signature["regex"], content, re.I):
                            found = True
                            break
                
                if found and tech_name not in self.results["technologies"]:
                    self.results["technologies"].append(tech_name)
                    self.log.info(f"Technologie détectée: {tech_name}")
            
            # Chercher des scripts et bibliothèques JS courantes
            soup = BeautifulSoup(content, 'html.parser')
            for script in soup.find_all("script", src=True):
                src = script["src"]
                # Détecter les bibliothèques JS courantes
                js_libs = {
                    "jQuery": r'jquery[-\.][0-9\.]+(?:\.min)?\.js',
                    "Bootstrap": r'bootstrap[-\.][0-9\.]+(?:\.min)?\.js',
                    "MomentJS": r'moment[-\.][0-9\.]+(?:\.min)?\.js',
                    "AngularJS": r'angular[-\.][0-9\.]+(?:\.min)?\.js',
                    "React": r'react[-\.][0-9\.]+(?:\.min)?\.js',
                    "Vue.js": r'vue[-\.][0-9\.]+(?:\.min)?\.js',
                    "Lodash": r'lodash[-\.][0-9\.]+(?:\.min)?\.js',
                    "Axios": r'axios[-\.][0-9\.]+(?:\.min)?\.js',
                }
                
                for lib_name, pattern in js_libs.items():
                    if re.search(pattern, src, re.I):
                        if lib_name not in self.results["technologies"]:
                            self.results["technologies"].append(lib_name)
                            self.log.info(f"Bibliothèque JS détectée: {lib_name}")
            
        except Exception as e:
            self.log.error(f"Erreur lors de l'identification des technologies: {str(e)}")
            
    def discover_subdomains(self):
        """Découvre les sous-domaines via diverses méthodes"""
        self.log.info(f"Recherche de sous-domaines pour {self.domain}")
        
        # Extrait le domaine principal (exemple.com à partir de sub.exemple.com)
        parts = self.domain.split('.')
        if len(parts) > 2:
            root_domain = '.'.join(parts[-2:])
        else:
            root_domain = self.domain
            
        # Méthode 1: Certificats SSL via crt.sh
        self._discover_subdomains_crtsh(root_domain)
        
        # Méthode 2: DNS bruteforce avec des sous-domaines courants
        self._discover_subdomains_bruteforce(root_domain)
        
        # Supprimer les doublons et trier
        self.results["subdomains"] = sorted(list(set(self.results["subdomains"])))
        
        self.log.info(f"Sous-domaines trouvés: {len(self.results['subdomains'])}")
    
    def _discover_subdomains_crtsh(self, domain):
        """Découvre les sous-domaines via crt.sh (Certificate Transparency)"""
        try:
            self.log.info(f"Recherche de sous-domaines via crt.sh pour {domain}")
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for item in data:
                        name = item.get('name_value', '').lower()
                        # Filtrer les certificats wildcard et extraire les sous-domaines
                        if name and '*' not in name:
                            for subdomain in name.split('\n'):
                                if subdomain.endswith(f".{domain}") and subdomain not in self.results["subdomains"]:
                                    self.results["subdomains"].append(subdomain)
                except:
                    self.log.error(f"Erreur lors du parsing des données crt.sh pour {domain}")
        except Exception as e:
            self.log.error(f"Erreur lors de la recherche crt.sh: {str(e)}")
    
    def _discover_subdomains_bruteforce(self, domain):
        """Découvre les sous-domaines par bruteforce de noms courants"""
        common_subdomains = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", 
            "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", 
            "dns", "host", "dev", "app", "api", "docs", "admin", "backend", "staging"
        ]
        
        self.log.info(f"Bruteforce de sous-domaines courants pour {domain}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_subdomain, f"{sub}.{domain}"): sub for sub in common_subdomains}
            for future in concurrent.futures.as_completed(futures):
                sub = futures[future]
                try:
                    is_valid = future.result()
                    if is_valid:
                        self.log.info(f"Sous-domaine trouvé: {sub}.{domain}")
                except Exception as e:
                    self.log.error(f"Erreur lors du bruteforce de sous-domaines: {str(e)}")
    
    def _check_subdomain(self, subdomain):
        """Vérifie si un sous-domaine existe en essayant de résoudre son adresse IP"""
        try:
            socket.gethostbyname(subdomain)
            if subdomain not in self.results["subdomains"]:
                self.results["subdomains"].append(subdomain)
            return True
        except:
            return False
    
    def analyze_javascript(self):
        """Analyse les fichiers JavaScript pour trouver des endpoints"""
        self.log.info(f"Analyse des fichiers JavaScript pour {self.target}")
        
        try:
            response = http_tools.send_request(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Trouver tous les scripts
            js_urls = []
            for script in soup.find_all("script", src=True):
                js_url = script["src"]
                
                # Convertir les URL relatives en absolues
                if js_url.startswith("//"):
                    js_url = f"{self.parsed_url.scheme}:{js_url}"
                elif js_url.startswith("/"):
                    js_url = f"{self.base_url}{js_url}"
                elif not js_url.startswith(("http://", "https://")):
                    js_url = f"{self.base_url}/{js_url}"
                
                js_urls.append(js_url)
            
            # Analyser chaque fichier JS
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._analyze_js_file, url): url for url in js_urls}
                for future in concurrent.futures.as_completed(futures):
                    url = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        self.log.error(f"Erreur lors de l'analyse du fichier JS {url}: {str(e)}")
            
        except Exception as e:
            self.log.error(f"Erreur lors de l'analyse des fichiers JavaScript: {str(e)}")
    
    def _analyze_js_file(self, url):
        """Analyse un fichier JavaScript pour trouver des endpoints"""
        try:
            # Ajouter un délai en mode furtif
            if self.stealth:
                time.sleep(1)
                
            response = http_tools.send_request(url)
            if response.status_code == 200:
                js_content = response.text
                
                # Rechercher des URL, endpoints API et chemins
                patterns = [
                    r'(?:"|\'|\`)(\/[a-zA-Z0-9_\-\.\/]+)(?:"|\'|\`)',  # Chemins relatifs
                    r'(?:"|\')https?:\/\/[^"\']+(?:"|\')(?=\.)',  # URLs complètes
                    r'(?:url|href|action|src)(?:\s*:\s*|\s*=\s*)(?:"|\'|\`)([^"\'`]+)(?:"|\'|\`)',  # Attributs contenant des URLs
                    r'\.ajax\s*\(\s*\{\s*url\s*:\s*(?:"|\')([^"\']+)(?:"|\')(?=\.)' # Appels AJAX
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        if match and len(match) > 1:  # Ignorer les matches trop courts
                            endpoint = match
                            
                            # Normaliser et filtrer les endpoints
                            if endpoint.startswith("/") or endpoint.startswith("http"):
                                if endpoint not in self.results["endpoints"]:
                                    self.results["endpoints"].append(endpoint)
                                    self.log.debug(f"Endpoint trouvé dans JS: {endpoint}")
                
        except Exception as e:
            self.log.error(f"Erreur lors de l'analyse du fichier JS {url}: {str(e)}")
    
    def analyze_site_structure(self):
        """Analyse la structure du site pour découvrir des liens et endpoints intéressants"""
        self.log.info(f"Analyse de la structure du site pour {self.target}")
        
        visited = set()
        to_visit = [self.target]
        max_depth = 1  # Limiter la profondeur de crawling pour l'analyse initiale
        
        while to_visit and len(visited) < 10:  # Limite à 10 pages pour cette phase initiale
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
                
            visited.add(current_url)
            
            try:
                self.log.debug(f"Analyse de la page: {current_url}")
                
                # Ajouter un délai en mode furtif
                if self.stealth:
                    time.sleep(1)
                    
                response = http_tools.send_request(current_url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Chercher tous les liens
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    
                    # Normaliser l'URL
                    if href.startswith("//"):
                        href = f"{self.parsed_url.scheme}:{href}"
                    elif href.startswith("/"):
                        href = f"{self.base_url}{href}"
                    elif not href.startswith(("http://", "https://", "#", "javascript:", "tel:", "mailto:")):
                        href = f"{self.base_url}/{href}"
                    
                    # Vérifier si l'URL est dans le même domaine
                    if self.domain in href:
                        # Ajouter aux endpoints si pas déjà présent
                        if href not in self.results["endpoints"]:
                            self.results["endpoints"].append(href)
                        
                        # Ajouter à la liste à visiter si pas déjà visité
                        if href not in visited and href not in to_visit:
                            to_visit.append(href)
                
                # Chercher les formulaires
                for form in soup.find_all("form"):
                    if form.get("action"):
                        action = form["action"]
                        
                        # Normaliser l'URL
                        if action.startswith("/"):
                            action = f"{self.base_url}{action}"
                        elif not action.startswith(("http://", "https://")):
                            action = f"{self.base_url}/{action}"
                            
                        # Ajouter aux endpoints
                        if action not in self.results["endpoints"]:
                            self.results["endpoints"].append(action)
                            self.log.debug(f"Formulaire trouvé: {action}")
                            
                        # Analyser les champs d'entrée
                        for input_field in form.find_all("input"):
                            field_name = input_field.get("name")
                            field_type = input_field.get("type", "")
                            
                            if field_name and field_type in ["text", "password", "file", "hidden"]:
                                self.log.debug(f"Champ trouvé dans {action}: {field_name} ({field_type})")
                
            except Exception as e:
                self.log.error(f"Erreur lors de l'analyse de {current_url}: {str(e)}")
        
        self.log.info(f"Endpoints trouvés: {len(self.results['endpoints'])}")

def run(target, threads=5, stealth=False):
    """Fonction principale pour lancer la reconnaissance"""
    recon = Recon(target, threads, stealth)
    return recon.run_full_recon()

if __name__ == "__main__":
    # Test direct du module
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        results = run(target_url)
        print(json.dumps(results, indent=4)) 