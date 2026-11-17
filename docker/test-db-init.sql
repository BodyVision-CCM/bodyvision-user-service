-- Initialisation de la base JETABLE des tests (voir docker-compose.test.yml). Mots de passe factices.
-- Reproduit, pour le seul schéma de ce service, ce que fait postgres/init/00_roles_schemas.sh du dépôt
-- https://github.com/BodyVision-CCM/bodyvision-infra-compose sur l'instance partagée : un rôle, son schéma, aucun accès pour les autres.
-- Équivalence vérifiée (propriétaire, droits, search_path, attributs du rôle). Si un droit change dans l'un des deux
-- fichiers, le changer aussi dans l'autre.

CREATE ROLE bv_utilisateurs LOGIN PASSWORD 'test-only-service-password';
CREATE SCHEMA utilisateurs AUTHORIZATION bv_utilisateurs;

REVOKE ALL ON SCHEMA utilisateurs FROM PUBLIC;
REVOKE ALL ON SCHEMA public       FROM PUBLIC;

ALTER ROLE bv_utilisateurs SET search_path = utilisateurs;