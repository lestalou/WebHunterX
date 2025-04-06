#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import datetime
from typing import Dict, Optional

# Utilisation de colorama pour la coloration des logs dans le terminal
try:
    from colorama import init, Fore, Style
    init(autoreset=True)  # Auto-reset des couleurs après chaque print
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Définir des placeholders si colorama n'est pas disponible
    class DummyFore:
        RED = ""
        GREEN = ""
        YELLOW = ""
        BLUE = ""
        MAGENTA = ""
        CYAN = ""
        WHITE = ""
        RESET = ""
    class DummyStyle:
        BRIGHT = ""
        RESET_ALL = ""
    Fore = DummyFore()
    Style = DummyStyle()

# Niveau de log global (peut être modifié dynamiquement)
DEFAULT_LOG_LEVEL = logging.INFO

# Dictionnaire pour stocker les loggers créés
loggers = {}

class ColoredFormatter(logging.Formatter):
    """
    Formatter personnalisé pour afficher des logs colorés dans le terminal
    """
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Style.BRIGHT + Fore.RED,
        'DEFAULT': Fore.WHITE
    }
    
    def __init__(self, fmt=None, datefmt=None, use_colors=True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and COLORS_AVAILABLE
    
    def format(self, record):
        # Sauvegarder le message original
        orig_msg = record.msg
        orig_levelname = record.levelname
        
        # Colorer le message si les couleurs sont activées
        if self.use_colors:
            color = self.COLORS.get(record.levelname, self.COLORS['DEFAULT'])
            record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
            record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        
        # Formater le message
        result = super().format(record)
        
        # Restaurer le message original
        record.msg = orig_msg
        record.levelname = orig_levelname
        
        return result

def setup_logger(name: str, log_file: Optional[str] = None, 
                level: int = None, use_colors: bool = True) -> logging.Logger:
    """
    Configure et retourne un logger avec le nom spécifié
    
    Args:
        name: Nom du logger
        log_file: Chemin du fichier de log (optionnel)
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        use_colors: Utiliser les couleurs dans les logs console
        
    Returns:
        Logger configuré
    """
    # Vérifier si le logger existe déjà
    if name in loggers:
        return loggers[name]
    
    # Créer un nouveau logger
    logger = logging.getLogger(name)
    
    # Définir le niveau de log
    if level is None:
        level = DEFAULT_LOG_LEVEL
    logger.setLevel(level)
    
    # Vérifier si le logger a déjà des handlers pour éviter les doublons
    if logger.handlers:
        return logger
    
    # Format des logs
    console_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    file_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Handler pour la console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(console_format, date_format, use_colors))
    logger.addHandler(console_handler)
    
    # Handler pour le fichier si spécifié
    if log_file:
        # Créer le répertoire des logs si nécessaire
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(file_format, date_format))
        logger.addHandler(file_handler)
    
    # Stocker le logger
    loggers[name] = logger
    
    return logger

def set_log_level(level: int, logger_name: Optional[str] = None):
    """
    Modifie le niveau de log
    
    Args:
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        logger_name: Nom du logger (si None, modifie le niveau de tous les loggers)
    """
    global DEFAULT_LOG_LEVEL
    DEFAULT_LOG_LEVEL = level
    
    if logger_name:
        if logger_name in loggers:
            loggers[logger_name].setLevel(level)
    else:
        # Modifier tous les loggers
        for logger in loggers.values():
            logger.setLevel(level)

def add_file_handler(logger_name: str, log_file: str):
    """
    Ajoute un handler de fichier à un logger existant
    
    Args:
        logger_name: Nom du logger
        log_file: Chemin du fichier de log
    """
    if logger_name not in loggers:
        return
    
    logger = loggers[logger_name]
    
    # Créer le répertoire des logs si nécessaire
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Format du fichier
    file_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Ajouter le handler de fichier
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(file_format, date_format))
    logger.addHandler(file_handler)

class LoggerContext:
    """
    Contexte temporaire pour le logger (pour utiliser with)
    """
    def __init__(self, logger, prefix=None, suffix=None, level=None):
        self.logger = logger
        self.prefix = prefix
        self.suffix = suffix
        self.level = level
        self.old_level = None
        
        # Attributs originaux à sauvegarder
        if isinstance(logger, logging.Logger):
            self.orig_log = logger._log
        else:
            self.orig_log = None
    
    def __enter__(self):
        # Sauvegarder le niveau actuel si nécessaire
        if self.level is not None and isinstance(self.logger, logging.Logger):
            self.old_level = self.logger.level
            self.logger.setLevel(self.level)
        
        # Redéfinir la méthode _log pour ajouter le préfixe/suffixe
        if isinstance(self.logger, logging.Logger) and (self.prefix or self.suffix):
            def custom_log(original_func, level, msg, args, **kwargs):
                if self.prefix:
                    msg = f"{self.prefix} {msg}"
                if self.suffix:
                    msg = f"{msg} {self.suffix}"
                return original_func(level, msg, args, **kwargs)
            
            self.logger._log = lambda level, msg, args, **kwargs: custom_log(self.orig_log, level, msg, args, **kwargs)
        
        return self.logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restaurer le niveau de log
        if self.old_level is not None and isinstance(self.logger, logging.Logger):
            self.logger.setLevel(self.old_level)
        
        # Restaurer la méthode _log
        if self.orig_log and isinstance(self.logger, logging.Logger):
            self.logger._log = self.orig_log

def get_all_loggers() -> Dict[str, logging.Logger]:
    """
    Retourne tous les loggers créés
    
    Returns:
        Dictionnaire des loggers (nom -> logger)
    """
    return loggers

def get_main_logger() -> logging.Logger:
    """
    Retourne le logger principal de l'application
    
    Returns:
        Logger principal
    """
    return setup_logger('webhunterx')

if __name__ == "__main__":
    # Test du logger
    logger = setup_logger(level=logging.DEBUG)
    
    logger.debug("Ceci est un message de DEBUG")
    logger.info("Ceci est un message d'INFO")
    logger.warning("Ceci est un message de WARNING")
    logger.error("Ceci est un message d'ERROR")
    logger.critical("Ceci est un message CRITIQUE")
    
    # Test du contexte temporaire
    with LoggerContext(logger, logging.ERROR):
        logger.debug("Ce message ne devrait pas apparaître")
        logger.error("Ce message d'erreur devrait apparaître")
    
    # Le niveau précédent est restauré
    logger.debug("Ce message devrait à nouveau apparaître") 