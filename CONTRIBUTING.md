# Guide de Contribution à WebHunterX

Tout d'abord, merci de considérer une contribution à WebHunterX ! C'est grâce à la communauté que ce projet peut continuer à s'améliorer et à évoluer.

## Table des matières

- [Code de Conduite](#code-de-conduite)
- [Comment puis-je contribuer ?](#comment-puis-je-contribuer-)
  - [Signaler des bugs](#signaler-des-bugs)
  - [Suggérer des améliorations](#suggérer-des-améliorations)
  - [Contribuer au code](#contribuer-au-code)
- [Normes de codage](#normes-de-codage)
- [Processus de développement](#processus-de-développement)
  - [Branches](#branches)
  - [Pull Requests](#pull-requests)
  - [Tests](#tests)
- [Documentation](#documentation)
- [Contact](#contact)

## Code de Conduite

Ce projet et tous ses participants sont régis par notre [Code de Conduite](CODE_OF_CONDUCT.md). En participant, vous acceptez de respecter ce code. Veuillez signaler tout comportement inacceptable à [contact@lestalou.fr](mailto:contact@lestalou.fr).

## Comment puis-je contribuer ?

### Signaler des bugs

Les bugs sont suivis comme des issues GitHub. Avant de créer un rapport de bug, vérifiez si le problème a déjà été signalé. Si c'est le cas, vous pouvez ajouter un commentaire pour fournir plus d'informations.

Lorsque vous créez un rapport de bug, veuillez inclure autant d'informations que possible :

- Utilisez un titre clair et descriptif
- Décrivez les étapes précises pour reproduire le problème
- Indiquez ce que vous vous attendiez à voir et ce que vous avez réellement vu
- Incluez votre environnement (OS, version Python, etc.)
- Joignez des captures d'écran si possible

### Suggérer des améliorations

Les suggestions d'améliorations sont également traitées comme des issues GitHub. Lorsque vous soumettez une suggestion :

- Utilisez un titre clair et descriptif
- Fournissez une description détaillée de l'amélioration souhaitée
- Expliquez pourquoi cette amélioration serait utile pour le projet
- Proposez une implémentation si possible

### Contribuer au code

1. Forkez le dépôt
2. Créez une branche pour votre travail (`git checkout -b feature/ma-nouvelle-fonctionnalite`)
3. Effectuez vos modifications (en suivant nos [normes de codage](#normes-de-codage))
4. Assurez-vous que les tests passent (`pytest`)
5. Committez vos changements (`git commit -m 'Ajout de ma fonctionnalité'`)
6. Poussez vers votre branche (`git push origin feature/ma-nouvelle-fonctionnalite`)
7. Ouvrez une Pull Request

## Normes de codage

### Python

- Suivez la norme [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Utilisez des docstrings au format Google pour documenter les fonctions et les classes
- Écrivez des tests unitaires pour vos fonctionnalités
- Maintenez une couverture de code d'au moins 80%
- Utilisez des noms explicites pour les variables et les fonctions
- Limitez la longueur des lignes à 100 caractères

### Go

- Suivez les [conventions Go officielles](https://golang.org/doc/effective_go.html)
- Utilisez `gofmt` pour formater votre code
- Écrivez des tests pour vos fonctionnalités
- Documentez les fonctions exportées

## Processus de développement

### Branches

- `main` : branche principale, toujours en état de production
- `develop` : branche de développement, intégration continue
- `feature/*` : branches de fonctionnalités
- `bugfix/*` : branches de correction de bugs
- `release/*` : branches de préparation de release

### Pull Requests

Avant de soumettre une Pull Request, assurez-vous que :

1. Votre code suit nos normes de codage
2. Tous les tests passent
3. Vous avez ajouté des tests pour vos nouvelles fonctionnalités
4. Vous avez mis à jour la documentation si nécessaire
5. Votre branche est à jour avec la branche `develop`

### Tests

- Les tests unitaires doivent être écrits en utilisant `pytest`
- Les tests d'intégration doivent être placés dans le répertoire `tests/integration/`
- Les tests de performance doivent être placés dans le répertoire `tests/performance/`
- Exécutez tous les tests avant de soumettre une Pull Request

## Documentation

- La documentation doit être mise à jour en même temps que le code
- Les modifications importantes de l'API doivent être documentées dans la section appropriée
- Les exemples de code doivent être testés pour s'assurer qu'ils fonctionnent

## Ajout de nouveaux modules de vulnérabilité

Pour ajouter un nouveau module de détection de vulnérabilité :

1. Créez un fichier dans le répertoire `webhunterx/` (Python) ou `webhunterx/modules_go/` (Go)
2. Suivez le modèle des modules existants pour maintenir une interface cohérente
3. Implémentez au minimum les fonctions suivantes :
   - Détection des points d'injection
   - Méthodes de test des vulnérabilités
   - Génération de rapports
4. Ajoutez des payloads spécifiques dans le répertoire `webhunterx/payloads/`
5. Mettez à jour le fichier principal `webhunterx.py` pour intégrer votre module
6. Documentez votre module dans la documentation

## Contact

Si vous avez des questions ou besoin d'aide, vous pouvez :

- Ouvrir une issue GitHub
- Rejoindre notre [Discord](https://discord.gg/webhunterx)
- Envoyer un email à [contact@lestalou.fr](mailto:contact@lestalou.fr)

---

Encore merci pour votre contribution à WebHunterX ! 