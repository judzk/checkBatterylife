# checkBatterylife
Package &amp; Script pour remonter les informations batterie sous WAPT et déclencher un ticket GLPI

# Pré-requis
* Installer le module de logging : https://github.com/RootITUp/Logging/wiki
* Créer un utilisateur avec les droits de lecture sur la base WAPT
* Avoir un accès à l'API GLPI

# Configuration
## Script GLPI
Renseigner le fichier config.ini avec vos infos perso
## Package WAPT
* Déplacer le fichier `setup.py` dans votre package WAPT
* Dans le fichier `control`, on peut fixer la date d'audit avec la ligne ```audit_schedule    : 30d``` pour avoir une date minimal d'audit des portables

# Requète pour le reporting WAPT
```
SELECT
   hosts.computer_name as computer,
   last_audit_on::timestamp as time,
   (replace(replace(hostpackagesstatus.last_audit_output,'Auditing',''),'ecl-checkBatteryLife',''))::json->>'returnReason' as result
FROM
   hostpackagesstatus
   LEFT JOIN hosts on hosts.uuid = hostpackagesstatus.host_id
WHERE hostpackagesstatus.last_audit_output ILIKE '%%NOK%%' AND hostpackagesstatus.package = 'ecl-checkBatteryLife'
 order by time
```

# Remerciement
Merci à Chouaib pour avoir traduit le script original en Pytnon