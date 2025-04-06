#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import random
import logging
import requests
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urlparse

# Importation du logger
from webhunterx.utils.logger import setup_logger

# Configuration du logger
logger = setup_logger('http_tools')

class HTTPClient:
    """
    Client HTTP avec fonctionnalités avancées pour le scanning de sécurité
    """
    
    # Liste des User-Agents par défaut
    DEFAULT_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "WebHunterX/1.0 (Security Testing Framework)"
    ]
    
    def __init__(self, 
                 timeout: int = 30, 
                 max_retries: int = 3,
                 user_agent: Optional[str] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 proxy: Optional[str] = None,
                 rotate_user_agent: bool = False,
                 verify_ssl: bool = True,
                 follow_redirects: bool = True,
                 max_redirects: int = 5,
                 delay: float = 0):
        """
        Initialise le client HTTP
        
        Args:
            timeout: Timeout en secondes pour les requêtes
            max_retries: Nombre maximum de tentatives en cas d'erreur
            user_agent: User-Agent à utiliser (si None, utilise un UA par défaut)
            cookies: Cookies à inclure dans les requêtes
            headers: Headers HTTP additionnels
            proxy: Proxy à utiliser (format: http://user:pass@host:port)
            rotate_user_agent: Rotation automatique des User-Agents
            verify_ssl: Vérification des certificats SSL
            follow_redirects: Suivre les redirections
            max_redirects: Nombre maximum de redirections à suivre
            delay: Délai entre les requêtes (en secondes)
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or random.choice(self.DEFAULT_USER_AGENTS)
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.proxy = proxy
        self.rotate_user_agent = rotate_user_agent
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.delay = delay
        
        # Si user_agent n'est pas dans les headers, l'ajouter
        if 'User-Agent' not in self.headers and user_agent is None:
            self.headers['User-Agent'] = self.user_agent
        
        # Configurer la session requests
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        
        # Configurer le proxy
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        # Statistiques
        self.stats = {
            'requests': 0,
            'success': 0,
            'errors': 0,
            'redirects': 0,
            'retries': 0
        }
        
        # Dernière requête
        self.last_request_time = 0
    
    def _wait_delay(self):
        """Attend le délai entre les requêtes"""
        if self.delay > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
    
    def _rotate_user_agent(self):
        """Change le User-Agent pour la prochaine requête"""
        if self.rotate_user_agent:
            new_ua = random.choice(self.DEFAULT_USER_AGENTS)
            self.headers['User-Agent'] = new_ua
            self.session.headers.update({'User-Agent': new_ua})
    
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Effectue une requête HTTP avec gestion des erreurs et des délais
        
        Args:
            method: Méthode HTTP (GET, POST, etc.)
            url: URL cible
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Objet Response de requests
        """
        # Attendre le délai si nécessaire
        self._wait_delay()
        
        # Rotation du User-Agent si activée
        if self.rotate_user_agent:
            self._rotate_user_agent()
        
        # Mise à jour des compteurs
        self.stats['requests'] += 1
        self.last_request_time = time.time()
        
        # Configurer les options de requête
        request_options = {
            'timeout': self.timeout,
            'verify': self.verify_ssl,
            'allow_redirects': self.follow_redirects,
            **kwargs
        }
        
        # Limiter le nombre de redirections si nécessaire
        if self.follow_redirects and self.max_redirects > 0:
            request_options['max_redirects'] = self.max_redirects
        
        # Tentatives multiples en cas d'erreur
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.session.request(method, url, **request_options)
                
                # Mise à jour des statistiques
                self.stats['success'] += 1
                if response.history:
                    self.stats['redirects'] += len(response.history)
                
                return response
            
            except (requests.RequestException, requests.ConnectionError, 
                   requests.Timeout, requests.TooManyRedirects) as e:
                self.stats['errors'] += 1
                
                # Journaliser l'erreur
                logger.error(f"Erreur lors de la requête {method} vers {url} (tentative {attempt}/{self.max_retries}): {str(e)}")
                
                # Réessayer ou lever l'exception
                if attempt < self.max_retries:
                    self.stats['retries'] += 1
                    logger.info(f"Nouvelle tentative dans 2 secondes...")
                    time.sleep(2)  # Attendre avant la prochaine tentative
                else:
                    logger.error(f"Nombre maximum de tentatives atteint pour {url}")
                    raise
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Effectue une requête GET
        
        Args:
            url: URL cible
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Objet Response de requests
        """
        return self._make_request('GET', url, **kwargs)
    
    def post(self, url: str, data: Optional[Dict[str, Any]] = None, 
             json: Optional[Dict[str, Any]] = None, **kwargs) -> requests.Response:
        """
        Effectue une requête POST
        
        Args:
            url: URL cible
            data: Données à envoyer (form-data)
            json: Données à envoyer (JSON)
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Objet Response de requests
        """
        return self._make_request('POST', url, data=data, json=json, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """
        Effectue une requête HEAD
        
        Args:
            url: URL cible
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Objet Response de requests
        """
        return self._make_request('HEAD', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> requests.Response:
        """
        Effectue une requête OPTIONS
        
        Args:
            url: URL cible
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Objet Response de requests
        """
        return self._make_request('OPTIONS', url, **kwargs)
    
    def put(self, url: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> requests.Response:
        """
        Effectue une requête PUT
        
        Args:
            url: URL cible
            data: Données à envoyer
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Objet Response de requests
        """
        return self._make_request('PUT', url, data=data, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """
        Effectue une requête DELETE
        
        Args:
            url: URL cible
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Objet Response de requests
        """
        return self._make_request('DELETE', url, **kwargs)
    
    def patch(self, url: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> requests.Response:
        """
        Effectue une requête PATCH
        
        Args:
            url: URL cible
            data: Données à envoyer
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Objet Response de requests
        """
        return self._make_request('PATCH', url, data=data, **kwargs)

    def activate_stealth_mode(self):
        """
        Active le mode furtif (rotation des User-Agents, délais aléatoires)
        """
        self.rotate_user_agent = True
        self.delay = random.uniform(1.0, 3.0)
        logger.info("Mode furtif activé")
    
    def deactivate_stealth_mode(self):
        """
        Désactive le mode furtif
        """
        self.rotate_user_agent = False
        self.delay = 0
        logger.info("Mode furtif désactivé")
    
    def update_cookies(self, cookies: Dict[str, str]):
        """
        Met à jour les cookies de la session
        
        Args:
            cookies: Nouveaux cookies à ajouter/mettre à jour
        """
        self.cookies.update(cookies)
        self.session.cookies.update(cookies)
    
    def update_headers(self, headers: Dict[str, str]):
        """
        Met à jour les headers de la session
        
        Args:
            headers: Nouveaux headers à ajouter/mettre à jour
        """
        self.headers.update(headers)
        self.session.headers.update(headers)
    
    def get_stats(self) -> Dict[str, int]:
        """
        Retourne les statistiques des requêtes
        
        Returns:
            Dictionnaire des statistiques
        """
        return self.stats
    
    def reset_stats(self):
        """
        Réinitialise les statistiques
        """
        self.stats = {
            'requests': 0,
            'success': 0,
            'errors': 0,
            'redirects': 0,
            'retries': 0
        }
    
    def close(self):
        """
        Ferme la session HTTP
        """
        self.session.close()

def download_file(url: str, output_path: str, 
                 headers: Optional[Dict[str, str]] = None, 
                 proxy: Optional[str] = None,
                 timeout: int = 30,
                 verify_ssl: bool = True) -> bool:
    """
    Télécharge un fichier à partir d'une URL
    
    Args:
        url: URL du fichier à télécharger
        output_path: Chemin où sauvegarder le fichier
        headers: Headers HTTP à utiliser
        proxy: Proxy à utiliser
        timeout: Timeout en secondes
        verify_ssl: Vérification des certificats SSL
        
    Returns:
        True si le téléchargement a réussi, False sinon
    """
    try:
        # Configurer les proxies si spécifiés
        proxies = None
        if proxy:
            proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Configurer les headers de base
        if headers is None:
            headers = {
                'User-Agent': random.choice(HTTPClient.DEFAULT_USER_AGENTS)
            }
        
        # Effectuer la requête avec streaming activé
        response = requests.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=verify_ssl,
            stream=True
        )
        
        # Vérifier le code de statut
        response.raise_for_status()
        
        # Écrire le contenu dans un fichier
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        logger.info(f"Fichier téléchargé avec succès: {url} -> {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement de {url}: {str(e)}")
        return False

def is_url_reachable(url: str, timeout: int = 5, verify_ssl: bool = False) -> bool:
    """
    Vérifie si une URL est accessible
    
    Args:
        url: URL à vérifier
        timeout: Timeout en secondes
        verify_ssl: Vérification des certificats SSL
        
    Returns:
        True si l'URL est accessible, False sinon
    """
    try:
        response = requests.head(
            url,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True
        )
        return response.status_code < 400
    except:
        return False

def extract_domain(url: str) -> str:
    """
    Extrait le domaine d'une URL
    
    Args:
        url: URL à analyser
        
    Returns:
        Domaine extrait
    """
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Supprimer le port s'il existe
    if ':' in domain:
        domain = domain.split(':')[0]
    
    return domain

def normalize_url(url: str) -> str:
    """
    Normalise une URL (ajoute http:// si nécessaire)
    
    Args:
        url: URL à normaliser
        
    Returns:
        URL normalisée
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Supprimer les barres obliques à la fin
    while url.endswith('/'):
        url = url[:-1]
    
    return url 