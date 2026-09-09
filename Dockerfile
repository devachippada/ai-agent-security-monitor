# AI Agent Security Monitor -- single-container production image.
#
# Builds the React/Vite frontend, then bakes it into the FastAPI backend
# image as static files (served by app/main.py's SPA-fallback route) so the
# whole app deploys as ONE service with no separate frontend host, no CORS
# configuration, and no API-base-URL environment variable -- the frontend
# already calls a same-origin "/api" (see frontend/src/api/client.ts).
#
# The labeled prompt-injection corpus and the offline-trained Isolation
# Forest anomaly model are also generated at build time (seeded, so results
# are reproducible -- the same numbers documented in README.md's "Phase 2
# status" section), rather than shipping pre-trained binaries in git.

# ---- Stage 1: build the frontend ----
FROM node:20-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: backend runtime, serving the built frontend too ----
FROM python:3.11-slim AS runtime
WORKDIR /app/backend

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./

# Generate the labeled dataset and train + evaluate the anomaly model.
# Both are deterministic (fixed seeds), matching what start.sh does for a
# local run and what the README documents.
RUN python scripts/build_dataset.py \
 && python train_model.py --n-samples 2000 --contamination 0.05 --seed 42 \
 && python evaluate_model.py --n-normal 400 --n-abnormal 400 --seed 1337

# Built frontend -> served by main.py's static-files/SPA-fallback block.
COPY --from=frontend-build /app/frontend/dist ./static

# Railway (and most PaaS hosts) inject $PORT at runtime; default it for
# `docker run` / other hosts that don't.
ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
