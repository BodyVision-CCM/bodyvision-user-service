#!/bin/sh
# Point d'entrée du conteneur : applique les migrations puis lance la commande (uvicorn par défaut).
#
# RUN_MIGRATIONS=true  (défaut) : pratique en développement et avec une seule instance.
# RUN_MIGRATIONS=false           : à utiliser dès qu'il y a plusieurs réplicas (Kubernetes) ; les
#                                  migrations tournent alors dans un Job dédié (`alembic upgrade head`).
#                                  (Un verrou PostgreSQL évite déjà que deux instances migrent en même temps.)
set -eu

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    echo '{"level":"INFO","service":"auth","message":"alembic upgrade head"}'
    alembic upgrade head
fi

# exec : uvicorn devient le processus principal et reçoit directement SIGTERM (arrêt propre).
exec "$@"
