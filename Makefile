# Convenience wrapper around the per-component build/run commands.
# See README.md for the full step-by-step execution plan and the
# rationale behind running the sensor outside Docker for local dev.

.PHONY: sensor-preflight sensor-build sensor-run broker-build broker-run \
        hunter-install hunter-run compose-up compose-down

sensor-preflight:
	./scripts/verify_caps.sh

sensor-build:
	cd sensor && cargo build --release -p cyber-patrol-loader

sensor-run: sensor-build
	sudo ./sensor/target/release/cyber-patrol-loader

broker-build:
	cd broker && go build -o bin/broker .

broker-run: broker-build
	sudo mkdir -p /var/lib/cyber-patrol && sudo chown "$$(id -u)":"$$(id -g)" /var/lib/cyber-patrol
	./broker/bin/broker -map-path=/sys/fs/bpf/cyber_patrol/EVENTS -hunter-url=http://localhost:8000 \
		-overflow-path=/var/lib/cyber-patrol/overflow.jsonl -audit-path=/var/lib/cyber-patrol/audit.jsonl

hunter-install:
	cd hunter && pip install -r requirements.txt

hunter-run:
	cd hunter && uvicorn app:app --host 0.0.0.0 --port 8000

compose-up:
	docker compose up --build

compose-down:
	docker compose down
