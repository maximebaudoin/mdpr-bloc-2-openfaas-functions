## Installer OpenFaas

Pour installer OpenFaas, on va utiliser Helm qui est un utilitaire pour gérer les paquets kubernetes :

1. `curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3`
2. `chmod 700 get_helm.sh`
3. `./get_helm.sh`

Création des namespaces :

4. `kubectl create namespace openfaas`
5. `kubectl create namespace openfaas-fn`

Ajout du repository OpenFaas Community :

6. `helm repo add openfaas https://openfaas.github.io/faas-netes/`
7. `helm repo update`

**Installation d'OpenFaas :**

```bash
helm upgrade openfaas openfaas/openfaas \ 
  --install \
  --namespace openfaas \
  --set functionNamespace=openfaas-fn \
  --set generateBasicAuth=true \
  --set gateway.serviceType=NodePort
```

Affichage du mot de passe :

```bash
PASSWORD=$(kubectl get secret -n openfaas basic-auth -o jsonpath="{.data.basic-auth-password}" | base64 -d)
echo $PASSWORD
```

Connexion en CLI pour utiliser les commandes plus tard :
```bash
faas-cli login --gateway http://localhost:8080 \
  --username admin \
  --password "$PASSWORD"
```

Laisser la commande suivante tourner pour accéder à l'interface web :

`kubectl port-forward -n openfaas svc/gateway 8080:8080`

**Nom d'utilisateur** : admin\
**Mot de passe** : *Affiché plus haut avec une commande*

## Création d'une fonction

`faas-cli new NOM_DE_LA_FONCTION --lang LANGAGE`

## Lancement en local pour dev et tester en direct

`faas-cli local-run --port 8088 --watch`

## Déploiement des fonctions sur OpenFaas

Pour déployer les fonctions, exécuter ces commandes dans l'ordre (à exécuter à chaque modification du code) :

`faas-cli build -f stack.yaml`\
`faas-cli push -f stack.yaml`\
`faas-cli deploy -f stack.yaml`

