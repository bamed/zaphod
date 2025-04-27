### Makefile
up:
	docker-compose up --build

down:
	docker-compose down

rebuild:
	docker-compose build --no-cache

logs:
	docker-compose logs -f

restart:
	docker-compose down && docker-compose up --build
