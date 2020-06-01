build:
	docker-compose -f ./deploy/docker-compose.yml build --no-cache whitelister

run:
	docker-compose -f ./deploy/docker-compose.yml up --remove-orphans whitelister

test:
	docker-compose -f ./deploy/docker-compose.yml up tests

lint:
	docker-compose -f ./deploy/docker-compose.yml up linter

down:
	docker-compose -f deploy/docker-compose.yml down