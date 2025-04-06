#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import html
import logging
import datetime
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger("webhunterx")

class ReportGenerator:
    """
    Générateur de rapports pour les modules de WebHunterX.
    Prend en charge plusieurs formats : JSON, HTML, CSV, et Markdown.
    """
    
    def __init__(self, module_name, output_dir=None):
        """
        Initialise le générateur de rapports.
        
        Args:
            module_name (str): Nom du module (ex: 'xss', 'sqli')
            output_dir (str, optional): Répertoire de sortie pour les rapports
        """
        self.module_name = module_name
        self.timestamp = int(time.time())
        self.date_humaine = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        # Définir le répertoire de sortie
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "output")
        
        # S'assurer que le répertoire existe
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        # Templates path
        self.templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates")
        
        logger.debug(f"Générateur de rapports initialisé pour le module {module_name}")
    
    def _sanitize_for_filename(self, text):
        """Nettoie un texte pour l'utiliser dans un nom de fichier"""
        return "".join(c for c in text if c.isalnum() or c in "._- ").replace(" ", "_")
    
    def generate_json(self, data, target_info=None, custom_filename=None):
        """
        Génère un rapport au format JSON.
        
        Args:
            data (dict/list): Données à inclure dans le rapport
            target_info (dict, optional): Informations sur la cible
            custom_filename (str, optional): Nom de fichier personnalisé
            
        Returns:
            str: Chemin vers le fichier de rapport généré
        """
        report = {
            "module": self.module_name,
            "timestamp": self.timestamp,
            "date": self.date_humaine,
            "resultats": data
        }
        
        if target_info:
            report["target_info"] = target_info
        
        if custom_filename:
            filename = f"{self._sanitize_for_filename(custom_filename)}.json"
        else:
            filename = f"{self.module_name}_report_{self.timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Rapport JSON généré : {filepath}")
        return filepath
    
    def generate_html(self, data, target_info=None, custom_filename=None, template="report_default.html"):
        """
        Génère un rapport au format HTML.
        
        Args:
            data (dict/list): Données à inclure dans le rapport
            target_info (dict, optional): Informations sur la cible
            custom_filename (str, optional): Nom de fichier personnalisé
            template (str, optional): Nom du fichier de template à utiliser
            
        Returns:
            str: Chemin vers le fichier de rapport généré
        """
        try:
            # Préparer l'environnement Jinja2
            env = Environment(loader=FileSystemLoader(self.templates_dir))
            template = env.get_template(template)
            
            # Préparer les données
            context = {
                "module": self.module_name,
                "timestamp": self.timestamp,
                "date": self.date_humaine,
                "resultats": data,
                "target_info": target_info or {}
            }
            
            # Rendre le template
            html_content = template.render(context)
            
            # Écrire dans un fichier
            if custom_filename:
                filename = f"{self._sanitize_for_filename(custom_filename)}.html"
            else:
                filename = f"{self.module_name}_report_{self.timestamp}.html"
            
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Rapport HTML généré : {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport HTML: {str(e)}")
            return None
    
    def generate_markdown(self, data, target_info=None, custom_filename=None):
        """
        Génère un rapport au format Markdown.
        
        Args:
            data (dict/list): Données à inclure dans le rapport
            target_info (dict, optional): Informations sur la cible
            custom_filename (str, optional): Nom de fichier personnalisé
            
        Returns:
            str: Chemin vers le fichier de rapport généré
        """
        if custom_filename:
            filename = f"{self._sanitize_for_filename(custom_filename)}.md"
        else:
            filename = f"{self.module_name}_report_{self.timestamp}.md"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # En-tête du rapport
            f.write(f"# Rapport {self.module_name.upper()} - WebHunterX\n\n")
            f.write(f"Date: {self.date_humaine}\n\n")
            
            # Informations sur la cible
            if target_info:
                f.write("## Informations sur la cible\n\n")
                for key, value in target_info.items():
                    f.write(f"- **{key}**: {value}\n")
                f.write("\n")
            
            # Résultats
            f.write("## Résultats\n\n")
            
            if isinstance(data, list):
                for i, item in enumerate(data, 1):
                    f.write(f"### Résultat {i}\n\n")
                    self._write_dict_to_markdown(f, item)
            else:
                self._write_dict_to_markdown(f, data)
            
            # Pied de page
            f.write("\n---\n\n")
            f.write("Rapport généré par WebHunterX - https://github.com/webhunterx\n")
        
        logger.info(f"Rapport Markdown généré : {filepath}")
        return filepath
    
    def _write_dict_to_markdown(self, file, data, indent=0):
        """Écrit un dictionnaire au format Markdown"""
        prefix = "  " * indent
        
        for key, value in data.items():
            if isinstance(value, dict):
                file.write(f"{prefix}- **{key}**:\n")
                self._write_dict_to_markdown(file, value, indent + 1)
            elif isinstance(value, list):
                file.write(f"{prefix}- **{key}**:\n")
                for item in value:
                    if isinstance(item, dict):
                        self._write_dict_to_markdown(file, item, indent + 1)
                    else:
                        file.write(f"{prefix}  - {item}\n")
            else:
                file.write(f"{prefix}- **{key}**: {value}\n")
    
    def generate_csv(self, data, target_info=None, custom_filename=None):
        """
        Génère un rapport au format CSV.
        
        Args:
            data (dict/list): Données à inclure dans le rapport
            target_info (dict, optional): Informations sur la cible
            custom_filename (str, optional): Nom de fichier personnalisé
            
        Returns:
            str: Chemin vers le fichier de rapport généré
        """
        import csv
        
        if custom_filename:
            filename = f"{self._sanitize_for_filename(custom_filename)}.csv"
        else:
            filename = f"{self.module_name}_report_{self.timestamp}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Aplatir les données pour le format CSV
        flat_data = []
        
        if isinstance(data, list):
            for item in data:
                flat_item = self._flatten_dict(item)
                flat_data.append(flat_item)
        else:
            flat_data.append(self._flatten_dict(data))
        
        # Écrire le CSV
        try:
            with open(filepath, 'w', encoding='utf-8', newline='') as f:
                if flat_data:
                    writer = csv.DictWriter(f, fieldnames=flat_data[0].keys())
                    writer.writeheader()
                    writer.writerows(flat_data)
            
            logger.info(f"Rapport CSV généré : {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport CSV: {str(e)}")
            return None
    
    def _flatten_dict(self, d, parent_key='', sep='_'):
        """Aplatit un dictionnaire multi-niveaux en un seul niveau pour CSV"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, ', '.join(str(x) for x in v)))
            else:
                items.append((new_key, v))
        
        return dict(items)
    
    def generate_poc(self, vuln_data, custom_filename=None):
        """
        Génère une preuve de concept HTML pour une vulnérabilité XSS.
        
        Args:
            vuln_data (dict): Données sur la vulnérabilité
            custom_filename (str, optional): Nom de fichier personnalisé
            
        Returns:
            str: Chemin vers le fichier PoC généré
        """
        if self.module_name != 'xss':
            logger.warning("La génération de PoC n'est actuellement supportée que pour le module XSS")
            return None
        
        try:
            # Préparer l'environnement Jinja2
            env = Environment(loader=FileSystemLoader(self.templates_dir))
            template = env.get_template("xss_poc.html")
            
            # Préparer les données
            context = {
                "date": self.date_humaine,
                "payload": vuln_data.get("payload", ""),
                "url": vuln_data.get("url", ""),
                "method": vuln_data.get("method", "GET"),
                "param": vuln_data.get("param", ""),
                "poc_url": self._build_poc_url(vuln_data),
                "description": vuln_data.get("description", "XSS Vulnerability"),
                "vector_type": vuln_data.get("type", "Reflected"),
                "context": vuln_data.get("context", "")
            }
            
            # Rendre le template
            html_content = template.render(context)
            
            # Écrire dans un fichier
            if custom_filename:
                filename = f"{self._sanitize_for_filename(custom_filename)}_poc.html"
            else:
                param_name = vuln_data.get("param", "unknown")
                filename = f"xss_poc_{param_name}_{self.timestamp}.html"
            
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"PoC XSS généré : {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du PoC: {str(e)}")
            return None
    
    def _build_poc_url(self, vuln_data):
        """Construit l'URL de preuve de concept"""
        import urllib.parse
        
        url = vuln_data.get("url", "")
        method = vuln_data.get("method", "GET")
        param = vuln_data.get("param", "")
        payload = vuln_data.get("payload", "")
        
        if method == "GET":
            # Analyser l'URL existante
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Mettre à jour le paramètre avec le payload
            query_params[param] = [payload]
            
            # Reconstruire la query string
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            
            # Reconstruire l'URL complète
            new_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            return new_url
        
        # Pour POST, on retourne simplement l'URL originale
        return url 