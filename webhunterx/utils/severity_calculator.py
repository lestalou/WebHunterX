#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Calculateur de sévérité pour les vulnérabilités détectées par WebHunterX.
Basé sur les critères CVSS mais simplifié pour une utilisation pratique.
"""

import logging
import math
from enum import Enum

logger = logging.getLogger("webhunterx")

class Impact(Enum):
    """Impact potentiel d'une vulnérabilité"""
    NONE = 0.0
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.9
    CRITICAL = 1.0

class Exploitability(Enum):
    """Facilité d'exploitation d'une vulnérabilité"""
    IMPOSSIBLE = 0.0
    DIFFICULT = 0.3
    MODERATE = 0.6
    EASY = 0.9
    TRIVIAL = 1.0

class AttackVector(Enum):
    """Vecteur d'attaque"""
    PHYSICAL = 0.2
    LOCAL = 0.4
    ADJACENT = 0.6
    NETWORK = 0.9
    INTERNET = 1.0

class VulnType(Enum):
    """Types de vulnérabilités"""
    XSS_REFLECTED = {"impact": Impact.MEDIUM, "exploitability": Exploitability.EASY}
    XSS_STORED = {"impact": Impact.HIGH, "exploitability": Exploitability.EASY}
    XSS_DOM = {"impact": Impact.MEDIUM, "exploitability": Exploitability.MODERATE}
    SQLI_ERROR = {"impact": Impact.HIGH, "exploitability": Exploitability.EASY}
    SQLI_BLIND = {"impact": Impact.MEDIUM, "exploitability": Exploitability.MODERATE}
    SQLI_TIME = {"impact": Impact.MEDIUM, "exploitability": Exploitability.MODERATE}
    CMD_INJECTION = {"impact": Impact.CRITICAL, "exploitability": Exploitability.EASY}
    RCE = {"impact": Impact.CRITICAL, "exploitability": Exploitability.EASY}
    LFI = {"impact": Impact.HIGH, "exploitability": Exploitability.EASY}
    RFI = {"impact": Impact.CRITICAL, "exploitability": Exploitability.EASY}
    SSRF = {"impact": Impact.HIGH, "exploitability": Exploitability.MODERATE}
    XXE = {"impact": Impact.HIGH, "exploitability": Exploitability.MODERATE}
    OPEN_REDIRECT = {"impact": Impact.LOW, "exploitability": Exploitability.EASY}
    CSRF = {"impact": Impact.MEDIUM, "exploitability": Exploitability.MODERATE}
    
class SeverityCalculator:
    """
    Calcule la sévérité d'une vulnérabilité en fonction de différents critères.
    """
    
    def __init__(self):
        """Initialise le calculateur de sévérité."""
        logger.debug("Initialisation du calculateur de sévérité")
    
    def calculate_from_type(self, vuln_type, context=None, mitigation=False):
        """
        Calcule la sévérité d'une vulnérabilité en fonction de son type.
        
        Args:
            vuln_type (str): Type de vulnérabilité (ex: XSS_REFLECTED, SQLI_ERROR)
            context (dict, optional): Contexte supplémentaire sur la vulnérabilité
            mitigation (bool, optional): Indique si des mesures d'atténuation sont en place
            
        Returns:
            dict: Score de sévérité (numérique et textuel) et détails du calcul
        """
        try:
            if isinstance(vuln_type, str):
                vuln_type = VulnType[vuln_type]
            
            # Obtenir les valeurs de base
            impact = vuln_type.value["impact"].value
            exploitability = vuln_type.value["exploitability"].value
            
            # Appliquer des modificateurs en fonction du contexte
            if context:
                impact = self._adjust_impact(impact, context)
                exploitability = self._adjust_exploitability(exploitability, context)
            
            # Réduire la sévérité si des mesures d'atténuation sont en place
            if mitigation:
                impact *= 0.7
            
            # Calculer le score brut (entre 0 et 10)
            raw_score = (impact * 0.6 + exploitability * 0.4) * 10
            
            # Arrondir à une décimale
            score = round(raw_score, 1)
            
            # Déterminer la sévérité textuelle
            severity = self._score_to_text(score)
            
            return {
                "score": score,
                "severity": severity,
                "raw_impact": impact,
                "raw_exploitability": exploitability,
                "details": {
                    "impact": impact * 10,
                    "exploitability": exploitability * 10,
                    "mitigation_applied": mitigation
                }
            }
            
        except (KeyError, ValueError) as e:
            logger.warning(f"Erreur lors du calcul de la sévérité: {str(e)}")
            # Valeur par défaut en cas d'erreur
            return {
                "score": 5.0,
                "severity": "medium",
                "details": {
                    "error": f"Type de vulnérabilité inconnu ou non supporté: {vuln_type}"
                }
            }
    
    def calculate_custom(self, impact, exploitability, attack_vector=AttackVector.INTERNET, context=None, mitigation=False):
        """
        Calcule la sévérité avec des valeurs personnalisées.
        
        Args:
            impact (float/Impact): Impact de la vulnérabilité (0-1 ou enum Impact)
            exploitability (float/Exploitability): Facilité d'exploitation (0-1 ou enum Exploitability)
            attack_vector (AttackVector, optional): Vecteur d'attaque
            context (dict, optional): Contexte supplémentaire
            mitigation (bool, optional): Indique si des mesures d'atténuation sont en place
            
        Returns:
            dict: Score de sévérité (numérique et textuel) et détails du calcul
        """
        # Convertir les enums en valeurs numériques si nécessaire
        if isinstance(impact, Impact):
            impact = impact.value
        if isinstance(exploitability, Exploitability):
            exploitability = exploitability.value
        if isinstance(attack_vector, AttackVector):
            attack_vector = attack_vector.value
            
        # Validation des entrées
        impact = min(max(impact, 0.0), 1.0)
        exploitability = min(max(exploitability, 0.0), 1.0)
        attack_vector = min(max(attack_vector, 0.0), 1.0)
        
        # Appliquer des modificateurs en fonction du contexte
        if context:
            impact = self._adjust_impact(impact, context)
            exploitability = self._adjust_exploitability(exploitability, context)
        
        # Réduire la sévérité si des mesures d'atténuation sont en place
        if mitigation:
            impact *= 0.7
        
        # Calculer le score avec le vecteur d'attaque comme facteur
        raw_score = (impact * 0.6 + exploitability * 0.25 + attack_vector * 0.15) * 10
        
        # Arrondir à une décimale
        score = round(raw_score, 1)
        
        # Déterminer la sévérité textuelle
        severity = self._score_to_text(score)
        
        return {
            "score": score,
            "severity": severity,
            "raw_impact": impact,
            "raw_exploitability": exploitability,
            "raw_attack_vector": attack_vector,
            "details": {
                "impact": impact * 10,
                "exploitability": exploitability * 10,
                "attack_vector": attack_vector * 10,
                "mitigation_applied": mitigation
            }
        }
    
    def analyze_xss(self, xss_type, context, waf_present=False, sensitive_data=False):
        """
        Calcule la sévérité spécifique d'une vulnérabilité XSS.
        
        Args:
            xss_type (str): Type de XSS (reflected, stored, dom)
            context (str): Contexte du XSS (html, attribute, js, etc.)
            waf_present (bool): Indique si un WAF est présent
            sensitive_data (bool): Indique si des données sensibles sont accessibles
            
        Returns:
            dict: Score de sévérité et détails
        """
        # Mapper les types de XSS aux types de vulnérabilités
        xss_type_map = {
            "reflected": "XSS_REFLECTED",
            "stored": "XSS_STORED", 
            "dom": "XSS_DOM"
        }
        
        # Contexte XSS et facteurs modificateurs
        context_impact = {
            "html": 1.0,         # Injection directe dans le HTML
            "attribute": 0.9,    # Injection dans un attribut
            "js": 1.1,           # Injection dans un contexte JavaScript
            "css": 0.8,          # Injection dans un style CSS
            "url": 0.85,         # Injection dans une URL
            "comment": 0.7       # Injection dans un commentaire
        }
        
        context_obj = {
            "context_modifier": context_impact.get(context.lower(), 1.0),
            "waf_present": waf_present,
            "sensitive_data": sensitive_data
        }
        
        # Utiliser les types mappés ou revenir au type XSS_REFLECTED par défaut
        vuln_type = xss_type_map.get(xss_type.lower(), "XSS_REFLECTED")
        
        return self.calculate_from_type(vuln_type, context=context_obj, mitigation=waf_present)
    
    def analyze_sqli(self, sqli_type, dbms="mysql", authentication_page=False, sensitive_data=True):
        """
        Calcule la sévérité spécifique d'une vulnérabilité SQLi.
        
        Args:
            sqli_type (str): Type de SQLi (error, blind, time)
            dbms (str): Système de gestion de base de données
            authentication_page (bool): Indique si la vulnérabilité est sur une page d'authentification
            sensitive_data (bool): Indique si des données sensibles sont accessibles
            
        Returns:
            dict: Score de sévérité et détails
        """
        # Mapper les types de SQLi aux types de vulnérabilités
        sqli_type_map = {
            "error": "SQLI_ERROR",
            "blind": "SQLI_BLIND",
            "time": "SQLI_TIME"
        }
        
        # Facteurs de risque par DBMS
        dbms_risk = {
            "mysql": 1.0,
            "postgresql": 1.0,
            "oracle": 1.1,      # Accès potentiel au système de fichiers
            "mssql": 1.1,       # xp_cmdshell et autres risques
            "sqlite": 0.8       # Généralement moins de privilèges
        }
        
        context_obj = {
            "dbms_modifier": dbms_risk.get(dbms.lower(), 1.0),
            "authentication_page": authentication_page,
            "sensitive_data": sensitive_data
        }
        
        # Utiliser les types mappés ou revenir au type SQLI_ERROR par défaut
        vuln_type = sqli_type_map.get(sqli_type.lower(), "SQLI_ERROR")
        
        return self.calculate_from_type(vuln_type, context=context_obj)
    
    def calculate_overall_risk(self, vulnerabilities):
        """
        Calcule le risque global en fonction d'une liste de vulnérabilités.
        
        Args:
            vulnerabilities (list): Liste de vulnérabilités avec leur sévérité
            
        Returns:
            float: Score de risque global (0-10)
        """
        if not vulnerabilities:
            return 0.0
            
        # Extraire les scores
        scores = []
        for vuln in vulnerabilities:
            if isinstance(vuln, dict) and "severity" in vuln:
                # Si on a un dictionnaire de vulnérabilité
                if isinstance(vuln["severity"], (int, float)):
                    scores.append(float(vuln["severity"]))
                elif isinstance(vuln["severity"], str):
                    # Convertir les sévérités textuelles en scores numériques
                    severity_map = {"low": 3.0, "medium": 5.0, "high": 8.0, "critical": 9.5}
                    scores.append(severity_map.get(vuln["severity"].lower(), 5.0))
            elif isinstance(vuln, (int, float)):
                # Si on a directement un score numérique
                scores.append(float(vuln))
                
        if not scores:
            return 0.0
            
        # Facteur de gravité: quadratique pour donner plus de poids aux vulnérabilités graves
        weighted_scores = [score ** 2 for score in scores]
        
        # Formule: moyenne pondérée avec bonus pour les vulnérabilités multiples
        base_score = sum(weighted_scores) / sum(1 for _ in weighted_scores)
        base_score = math.sqrt(base_score)  # Revenir à l'échelle 0-10
        
        # Bonus pour le nombre de vulnérabilités (plafonné)
        vuln_count_bonus = min(len(scores) * 0.2, 1.5)
        
        # Score final, plafonné à 10
        final_score = min(base_score + vuln_count_bonus, 10.0)
        
        return round(final_score, 1)
    
    def _adjust_impact(self, impact, context):
        """Ajuste l'impact en fonction du contexte"""
        # Modificateur de contexte (ex: html, js, etc. pour XSS)
        if "context_modifier" in context:
            impact *= context["context_modifier"]
            
        # Si la vulnérabilité est sur une page d'authentification ou de paiement
        if context.get("authentication_page", False):
            impact *= 1.2
            
        # Si des données sensibles sont accessibles
        if context.get("sensitive_data", False):
            impact *= 1.15
            
        # Si le DBMS a une incidence sur l'impact (SQLi)
        if "dbms_modifier" in context:
            impact *= context["dbms_modifier"]
            
        return min(impact, 1.0)  # Plafonner à 1.0
    
    def _adjust_exploitability(self, exploitability, context):
        """Ajuste l'exploitabilité en fonction du contexte"""
        # Si un WAF est présent, l'exploitation est plus difficile
        if context.get("waf_present", False):
            exploitability *= 0.8
            
        # Si l'exploitation nécessite des connaissances avancées
        if context.get("advanced_knowledge_required", False):
            exploitability *= 0.85
            
        # Si l'exploitation nécessite des privilèges particuliers
        if context.get("privileges_required", False):
            exploitability *= 0.7
            
        return min(exploitability, 1.0)  # Plafonner à 1.0
    
    def _score_to_text(self, score):
        """Convertit un score numérique en sévérité textuelle"""
        if score < 0.1:
            return "none"
        elif score < 4.0:
            return "low"
        elif score < 7.0:
            return "medium"
        elif score < 9.0:
            return "high"
        else:
            return "critical"


# Exemple d'utilisation
if __name__ == "__main__":
    calculator = SeverityCalculator()
    
    # Exemple: XSS stocké dans un contexte JavaScript
    xss_result = calculator.analyze_xss("stored", "js", waf_present=False, sensitive_data=True)
    print(f"Sévérité XSS stocké: {xss_result['score']} ({xss_result['severity']})")
    
    # Exemple: Injection SQL sur une page d'authentification
    sqli_result = calculator.analyze_sqli("error", "mysql", authentication_page=True)
    print(f"Sévérité SQLi: {sqli_result['score']} ({sqli_result['severity']})")
    
    # Exemple: Calcul de risque global pour un système
    vulnerabilities = [
        {"type": "XSS_REFLECTED", "severity": "medium"},
        {"type": "SQLI_ERROR", "severity": "high"},
        {"type": "OPEN_REDIRECT", "severity": "low"}
    ]
    overall_risk = calculator.calculate_overall_risk(vulnerabilities)
    print(f"Risque global: {overall_risk}") 