build:
	docker compose -f ./deploy/docker-compose.yml build --no-cache whitelister

run:
	# https://stackoverflow.com/a/2670143/6670698
	-docker rmi deploy_whitelister:latest
	COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker compose -f ./deploy/docker-compose.yml up --build --remove-orphans whitelister

test:
	docker compose -f ./deploy/docker-compose.yml up tests

lint:
	docker compose -f ./deploy/docker-compose.yml up linter

down:
	docker compose -f ./deploy/docker-compose.yml down