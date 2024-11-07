# Aplicación Web

## Comandos para migracion y DB
### Despues de agregar el identity
- add-migration InitialMigration -o Data/Migrations
- update-database
### Despues de agregar campos al modelo de identity
- add-migration AddPropertiesInUsers -o Data/Migrations
- update-database