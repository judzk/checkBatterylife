# checkBatterylife
Package &amp; Script pour remonter les informations batterie sous WAPT et déclencher un ticket GLPI

# Pré-requis
* Installer le module de logging : https://github.com/RootITUp/Logging/wiki
* Créer un utilisateur avec les droits de lecture sur la base WAPT
* Avoir un accès à l'API GLPI

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