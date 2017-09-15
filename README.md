# Instructions

## Prérequis

Pour utiliser le template, vous devez avoir un groupe de ressource existant.
Vous pouvez le créer dans le [Portal Azure](https://portal.azure.com/#create/Microsoft.ResourceGroup) ou avec la ligne de commande suivante :  
``` bash
az group create -n <resource-group-name> -l <location>
```

Le template est séparé en plusieurs fichiers qui doivent tous être disponible publiquement avec leur url.
La méthode recommandée est d'ajouter les fichiers dans un stockage blob et de générer un token SAS pour y acccéder ([tutorial](https://docs.microsoft.com/fr-fr/azure/azure-resource-manager/resource-manager-powershell-sas-token))

## Déployer
### Avec Azure CLI :

``` bash
az group deployment create --resource-group <resource-group-name> --template-uri <template-uri> --parameters <parameter-file-path>|<name=value>
```

## Edition

Si vous ajouter des ressources dans le template, veuillez suivre les [conventions de nommage](https://docs.microsoft.com/fr-fr/azure/architecture/best-practices/naming-conventions#naming-rules-and-restrictions) et préfixer par le paramètre `baseName`.