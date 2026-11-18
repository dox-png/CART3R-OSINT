# CART3R OSINT — PWA

Application web progressive (PWA) en Flask pour iPhone. Elle fournit une analyse technique limitée aux domaines publics : résolution DNS, adresses IP publiques et informations de certificat TLS.

## Fonctionnalités
- Interface mobile sombre rouge/noir.
- Ajout à l'écran d'accueil de l'iPhone.
- Analyse DNS et TLS d'un domaine saisi.
- Historique des analyses dans SQLite.
- Validation des domaines et blocage des adresses IP non publiques.
- En-têtes de sécurité et protection CSRF.

Ce projet n'est pas un moteur de recherche de personnes. Il ne collecte ni adresses privées, ni numéros personnels, ni profils sociaux.

## Déploiement sur Render
1. Décompresser l'archive.
2. Créer un dépôt GitHub et y importer tous les fichiers.
3. Sur Render, choisir **New + → Blueprint**.
4. Connecter le dépôt GitHub contenant `render.yaml`.
5. Laisser Render créer le service. Vérifier que la variable `SECRET_KEY` est générée.
6. Une fois le déploiement terminé, ouvrir l'URL HTTPS fournie par Render.

Important : SQLite sur un hébergement éphémère peut perdre son contenu lors d'un redéploiement ou redémarrage. Pour conserver l'historique durablement, ajouter un disque persistant ou remplacer SQLite par PostgreSQL. Ne pas y stocker de données personnelles.

## Installation sur iPhone
1. Ouvrir l'URL HTTPS du site dans Safari.
2. Appuyer sur le bouton **Partager**.
3. Choisir **Sur l'écran d'accueil**.
4. Activer **Ouvrir comme app web** si cette option est proposée.
5. Appuyer sur **Ajouter**.

L'icône apparaît sur l'écran d'accueil et le site s'ouvre en mode application.

## Développement local
Python 3.12 recommandé.

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell
.venv\\Scripts\\Activate.ps1

pip install -r requirements.txt
python app.py
```

Ouvrir http://127.0.0.1:5000.

## Avant une utilisation publique
- Définir une `SECRET_KEY` longue et aléatoire dans les variables d'environnement.
- Ajouter une limitation de débit persistante et une protection anti-abus au niveau de l'hébergeur.
- Configurer une base PostgreSQL pour les données persistantes.
- Vérifier les conditions d'utilisation des sources consultées.
- Faire auditer le code et la configuration de déploiement.
