# VulnCheck & Approve — Frontend

Console React de l'outil interne de validation sécuritaire des logiciels tiers.
Consomme l'API FastAPI (version SQLAlchemy) : validations, historique, base CVE,
tableau de bord et explicabilité du modèle de risque.

## Développement

```bash
npm install
npm run dev          # http://localhost:5173
```

Le serveur Vite relaie `/api` et `/health` vers `http://localhost:8000`
(voir `vite.config.js`). L'API doit donc tourner en local sur le port 8000.

## Production (Docker)

```bash
docker build -t vulncheck-frontend .
```

L'image nginx sert le build statique et relaie `/api` vers le service
`api:8000` du docker-compose (voir `nginx.conf`). Exemple de service :

```yaml
  frontend:
    build: ./frontend
    ports:
      - "8080:80"
    depends_on:
      - api
```

## Pages

| Route              | Écran                                                        |
|--------------------|--------------------------------------------------------------|
| `/`                | Valider un logiciel (formulaire + rapport + verdict)         |
| `/historique`      | Historique paginé, filtrable par verdict                     |
| `/historique/:id`  | Rapport archivé complet                                      |
| `/cves`            | Recherche dans la base CVE locale                            |
| `/cves/:cveId`     | Fiche CVE (CVSS, EPSS, KEV, configurations, références)      |
| `/tableau-de-bord` | Volumétrie, fraîcheur des synchros Airflow, graphiques       |
| `/modele`          | Moteur de risque actif et importance des variables           |
