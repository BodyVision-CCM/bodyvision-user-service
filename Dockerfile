# syntax=docker/dockerfile:1
#
# Image du service Auth. Deux cibles :
#   - runtime (défaut, DERNIÈRE étape) : image de production, sans outils de test
#   - test                              : même image + pytest et les tests
# Construire sans option produit donc toujours l'image de production.

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Utilisateur sans privilèges (le conteneur ne tourne jamais en root). /run/keys reçoit la clé de
# signature JWT : un volume nommé monté dessus hérite de ce propriétaire.
RUN useradd --system --uid 10001 --user-group --no-create-home app \
 && mkdir -p /run/keys \
 && chown app:app /run/keys

# Dépendances d'abord : cette couche n'est reconstruite que si requirements.txt change.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app app ./app
COPY --chown=app:app migrations ./migrations
COPY --chown=app:app alembic.ini entrypoint.sh ./
RUN chmod +x entrypoint.sh

USER app
EXPOSE 8000

# /healthz ne dépend d'aucun service externe : il dit seulement « le processus répond ».
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]


# ---------------------------------------------------------------------------------------------
FROM base AS test
USER root
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY --chown=app:app pytest.ini ./
COPY --chown=app:app tests ./tests
# Instantané du contrat OpenAPI : les tests de conformité le comparent au service.
COPY --chown=app:app contracts ./contracts
USER app
CMD ["pytest"]


# ---------------------------------------------------------------------------------------------
# Dernière étape = cible par défaut.
FROM base AS runtime
