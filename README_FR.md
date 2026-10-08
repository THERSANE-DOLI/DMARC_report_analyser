# Analyseur de rapports DMARC

*[English version](README.md)*

Page web pour lire facilement les rapports DMARC agrégés (`rua`) envoyés chaque jour par Google, Microsoft, Yahoo, GMX… à l'adresse déclarée dans votre enregistrement DMARC.

Les fichiers sont lus **directement dans le navigateur** : ils ne sont envoyés à aucun serveur.

**Version en ligne : https://thersane-doli.github.io/DMARC_report_analyser/**

## Deux versions dans le même dépôt

| | Version statique (`index.html`) | Version serveur (`index.php`) |
|---|---|---|
| Hébergement | N'importe quel hébergement statique, par exemple **GitHub Pages** | Serveur web avec PHP |
| Lecture des rapports | Dans le navigateur | Dans le navigateur (identique) |
| Requêtes DNS (PTR, contrôles DMARC / SPF / DKIM) | Via le DNS-over-HTTPS de Cloudflare (les IP et noms de domaine sont envoyés à Cloudflare) | Par votre serveur |
| Évolutions prévues | | Lecture des rapports depuis une boîte mail |

Les deux versions partagent l'interface (`assets/`), le lecteur de rapports et les traductions (`lang/`). `index.php` affiche simplement `index.html` en activant les fonctions serveur.

## Fonctionnalités

- Formats acceptés : `.xml`, `.gz` / `.xml.gz`, `.zip` (y compris un zip contenant des `.gz`)
- E-mails `.eml` : les rapports en pièce jointe sont extraits (y compris dans un e-mail transféré). Depuis Thunderbird, glisser l'e-mail sur le bureau puis déposer le fichier `.eml` dans la page
- Plusieurs fichiers à la fois, par glisser-déposer ou sélection
- Indicateurs : nombre de rapports et période couverte, messages, IP sources, taux de conformité DMARC, DKIM et SPF alignés, quarantaine / rejet
- Quatre vues :
  - **Par IP source** : volume, taux de conformité, domaines signataires DKIM, rapporteurs (cliquer sur une ligne pour voir le détail de l'IP)
  - **Enregistrements** : détail de chaque ligne de rapport (résultats DKIM avec sélecteur, SPF, `From`, enveloppe)
  - **Rapports** : rapporteur, période, politique publiée (`p`, `sp`, `pct`, `adkim`, `aspf`, `fo`)
  - **Domaines** : contrôle des enregistrements DNS actuels de chaque domaine
    - **DMARC** : politique, `sp` plus faible que `p`, `pct` < 100, `rua` absent, autorisation des destinations `rua` externes, enregistrements multiples, héritage depuis le domaine parent
    - **SPF** : présence, enregistrements multiples, mécanisme `all` final (`+all`, `?all`, `~all`, `-all`), `redirect=`, `ptr`
    - **DKIM** : pour chaque sélecteur vu dans les rapports, clé publiée ou révoquée, type et taille de clé (alerte sous 2048 bits), mode test, signature d'un domaine tiers non aligné
- **Vérifier un domaine** sans rapport : saisir un domaine (ou une adresse e-mail, ou une URL) et, si besoin, ses sélecteurs DKIM. Sans sélecteur, une liste de sélecteurs courants est testée. Lien partageable : `?domain=exemple.fr&selectors=mail`
- Filtres : recherche libre (IP, domaine, sélecteur DKIM, rapporteur…), domaine, rapporteur, échecs uniquement
- Résolution DNS inverse (PTR) des IP à la demande, IPv4 et IPv6
- Doublons ignorés (même rapport déposé deux fois)
- Interface en français et en anglais, détectée depuis le navigateur, modifiable par le bouton EN | FR (mémorisé dans le navigateur)
- Thème clair / sombre automatique

Un message est **conforme DMARC** quand DKIM *ou* SPF est valide *et aligné* sur le domaine du `From:`.

## Prérequis

- Un navigateur récent : Chrome / Edge 103+, Firefox 113+, Safari 16.4+ (décompression native `DecompressionStream`)
- Version serveur uniquement : PHP 7.3 ou supérieur (testé avec PHP 8.3)

## Installation

### Version statique sur GitHub Pages

1. Pousser le dépôt sur GitHub
2. Dans **Settings > Pages**, choisir *Deploy from a branch*, la branche `main` et le dossier `/ (root)`
3. La page est disponible à l'adresse `https://<utilisateur>.github.io/<dépôt>/`

GitHub Pages n'exécute pas le PHP : `index.php` y est ignoré, c'est `index.html` qui est servi.

### Version serveur

Copier le dossier sur un serveur web avec PHP. Aucune base de données ni dépendance à installer. Le `.htaccess` fourni fait servir `index.php` en priorité sous Apache (`DirectoryIndex index.php index.html`) ; sous nginx, mettre `index index.php index.html;`.

Pour un test en local :

```bash
php -S 127.0.0.1:8765
```

puis ouvrir http://127.0.0.1:8765/ (version serveur) ou http://127.0.0.1:8765/index.html (version statique).

## Configuration

### Dans `assets/parser.js`

| Constante | Défaut | Rôle |
|---|---|---|
| `MAX_XML_SIZE` | 50 Mo | Taille maximale d'un XML décompressé |
| `MAX_TOTAL_SIZE` | 200 Mo | Volume décompressé maximal pour un dépôt de fichiers |
| `MAX_ZIP_ENTRIES` | 50 | Nombre maximal de fichiers lus dans un zip |

### Dans `index.php`

| Constante | Défaut | Rôle |
|---|---|---|
| `DNS_RATE_LIMIT` | 1000 | Nombre maximal de requêtes DNS (PTR et TXT) par adresse IP de visiteur et par heure |

## Ajouter une langue

1. Copier `lang/en.js` en `lang/xx.js`, remplacer `.en =` par `.xx =` et traduire les valeurs (garder les clés et les `{0}`, `{1}`…)
2. Ajouter `<script src="lang/xx.js"></script>` dans `index.html`, à côté des autres langues

Les clés se terminant par `_html` peuvent contenir du HTML ; les autres sont échappées. Si le navigateur ne demande aucune des langues disponibles, la page s'affiche en anglais.

## Sécurité

Le contenu d'un rapport doit être considéré comme hostile : n'importe qui peut envoyer un faux rapport à votre adresse `rua=`. La page est conçue en conséquence :

- Tout le contenu des rapports est échappé à l'affichage
- `Content-Security-Policy` stricte (aucun script externe ni inline) : balise `<meta>` dans la version statique, en-tête HTTP dans la version serveur (avec `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`)
- XML avec `DOCTYPE` / `ENTITY` refusé (protection XXE et « billion laughs »)
- Limites de décompression contre les bombes gzip / zip, zip imbriqués refusés
- Les fichiers ne quittent jamais le navigateur
- Version serveur : les requêtes DNS n'acceptent que des adresses IP et noms de domaine valides et sont limitées par visiteur (`DNS_RATE_LIMIT`)

### Avant une mise en ligne de la version serveur

- Servir la page en **HTTPS**
- Interdire l'accès direct au dossier `src/`. Le `.htaccess` fourni le fait sous Apache ; sous **nginx**, ajouter par exemple :

  ```nginx
  location ~ ^/src/ { deny all; }
  location ~ /\. { deny all; }
  ```

## Structure

```
index.html            Page (version statique), utilisée aussi par index.php
index.php             Version serveur : sert index.html + requêtes DNS (PTR, TXT)
assets/parser.js      Lecture des rapports .xml / .gz / .zip dans le navigateur
assets/dns.js         Contrôles DNS DMARC / SPF / DKIM
assets/app.js         Affichage, filtres, tris, langue, PTR
assets/style.css      Styles (clair / sombre)
lang/en.js, fr.js     Traductions
src/DmarcParser.php   Lecteur de rapports en PHP, pour la future lecture d'une boîte mail
```

## Limites

- Seuls les rapports **agrégés** (`rua`) sont pris en charge, pas les rapports d'échec (`ruf`)
- Archives zip64 et zip chiffrés non pris en charge
- Au-delà de 2 000 lignes, le tableau est tronqué : affiner les filtres
- Aucun historique : chaque analyse repart des fichiers déposés
- Les contrôles DNS portent sur les enregistrements **actuels**, qui peuvent différer de ceux en vigueur aux dates des rapports
- SPF : les `include` ne sont pas encore développés (pas de comptage de la limite des 10 requêtes DNS)
- Le domaine organisationnel est approché par les deux derniers labels (pas de liste des suffixes publics) : résultat d'alignement approximatif pour les domaines en `.co.uk`, etc.

## Licence

Copyright (C) 2026 THERSANE

Ce programme est un logiciel libre, distribué sous licence [GNU GPL version 3](LICENSE) ou (à votre choix) toute version ultérieure. Il est fourni sans aucune garantie.
