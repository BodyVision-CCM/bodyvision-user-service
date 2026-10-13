# Raccourcis du dépôt Auth. `make help` liste les commandes.
# Pour lancer TOUS les services ensemble, voir le dépôt infra-compose (frère de ce dépôt).

.DEFAULT_GOAL := help
.PHONY: help test build

help: ## Affiche cette aide
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-6s %s\n", $$1, $$2}'

test: ## Lance les tests dans Docker, avec un PostgreSQL jetable (identique en CI)
	@docker compose -f docker-compose.test.yml run --rm --build tests; rc=$$?; \
	  docker compose -f docker-compose.test.yml down -v --remove-orphans >/dev/null 2>&1; exit $$rc

build: ## Construit l'image de production bodyvision/auth:dev
	docker build -t bodyvision/auth:dev .
