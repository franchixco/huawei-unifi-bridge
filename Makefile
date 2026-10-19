.DEFAULT_GOAL := up
.PHONY: up stop logs test

up:
	docker compose up -d --build
	@printf "\nDashboard: http://127.0.0.1:8091\nGenieACS UI: http://127.0.0.1:3002\nCWMP: bound to the LAN address in compose.yml (7547)\nStatus: docker compose ps\n"

stop:
	docker compose stop

logs:
	docker compose logs --tail=100 -f bridge

test:
	python3 -m unittest discover -s tests -v
