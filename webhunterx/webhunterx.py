#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import logging
import time

# Ajouter le répertoire parent au sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configuration du logger
try:
    from utils.logger import setup_logger
    
    # Configuration du logger
    logger = setup_logger('webhunterx')
except ImportError as e:
    print(f"Erreur d'importation du logger: {e}")
    # Fallback pour le logger en cas d'erreur
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('webhunterx')

try:
    # Tentative d'importation des modules core
    # Ils seront importés directement depuis le dossier core local
    from core import recon, crawler, sqli, xss, lfi, upload, login_bypass, reporter
    MODULES_AVAILABLE = True
except ImportError as e:
    # Modules core non disponibles, nous allons fonctionner en mode limité
    MODULES_AVAILABLE = False
    logger.warning(f"Attention: Certains modules ne sont pas disponibles: {e}")
    logger.info("Fonctionnement en mode limité.")

def main():
    """
    Point d'entrée principal pour WebHunterX
    """
    parser = argparse.ArgumentParser(description='WebHunterX - Un framework d\'analyse de vulnérabilités web')
    parser.add_argument('--target', '-t', help='URL ou domaine cible')
    parser.add_argument('--output', '-o', help='Fichier de sortie pour le rapport')
    parser.add_argument('--module', '-m', help='Module spécifique à exécuter (sqli, xss, lfi, etc.)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    if not args.target:
        parser.print_help()
        return
    
    # Afficher un message d'introduction
    logger.info("WebHunterX - Framework d'analyse de vulnérabilités web")
    logger.info(f"Cible: {args.target}")
    
    if not MODULES_AVAILABLE:
        logger.error("Impossible d'exécuter le scanner complet: les modules core ne sont pas disponibles.")
        logger.info("Veuillez utiliser les modules individuels directement:")
        logger.info("  python xss.py URL")
        logger.info("  python sqli.py URL")
        return
    
    # Si un module spécifique est demandé
    if args.module:
        if args.module.lower() == 'xss':
            logger.info("Exécution du module XSS")
            scanner = xss.XSSScanner(args.target)
            results = scanner.run(args.output)
        elif args.module.lower() == 'sqli':
            logger.info("Exécution du module SQLi")
            scanner = sqli.SQLiScanner(args.target)
            results = scanner.run(args.output)
        elif args.module.lower() == 'lfi':
            logger.info("Exécution du module LFI")
            scanner = lfi.LFIScanner(args.target)
            results = scanner.run(args.output)
        else:
            logger.error(f"Module {args.module} non reconnu")
            return
    else:
        # Exécution d'un scan complet
        logger.info("Exécution d'un scan complet")
        # TODO: Implémenter le scan complet
        
    logger.info("Scan terminé")
    
if __name__ == "__main__":
    main() 