# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# `sudo` is only needed for the scoped privileged-kill fallback in
# responder.py::_kill_via_script. Remove this layer and the sudoers rule
# below entirely if you rely solely on the Go broker's responder (see
# README "Response Mechanism").
RUN apt-get update \
    && apt-get install -y --no-install-recommends sudo \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# scripts/kill_pid.sh (repo root) is bind-mounted in at the path
# responder.py's _KILL_SCRIPT expects -- see docker-compose.yml's `hunter`
# service volumes. Kept out of the image build so the script can be
# updated/audited without a rebuild.
RUN mkdir -p /opt/cyber-patrol/scripts

RUN useradd --create-home --shell /usr/sbin/nologin hunter \
    && echo "hunter ALL=(root) NOPASSWD: /opt/cyber-patrol/scripts/kill_pid.sh" > /etc/sudoers.d/cyber-patrol \
    && chmod 0440 /etc/sudoers.d/cyber-patrol \
    && chown -R hunter:hunter /app

USER hunter
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
