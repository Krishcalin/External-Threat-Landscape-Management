# SKOPOS — the console and the API in one image.
#
# The SPA is built here and served by the API, which is what api/client.ts
# already assumes: it fetches relative `/api/v1` paths and carries no origin.
# One origin also means the CORS allowance stays a development-only concession
# rather than something a deployment has to widen.

# ---- stage 1: build the console -------------------------------------------
FROM node:22-alpine AS console

WORKDIR /build
# package files first so a source-only edit does not re-run the install layer.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
# `npm run build` is `tsc -b && vite build` — the typecheck is part of the
# build on purpose. An image that compiles a bundle from code that does not
# typecheck is an image that ships a bug the toolchain already found.
RUN npm run build

# ---- stage 2: the runtime --------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SKOPOS_CONSOLE_DIR=/app/frontend/dist

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ ./core/
COPY api/ ./api/
COPY collect/ ./collect/
COPY db/ ./db/
COPY tools/ ./tools/
COPY main.py ./
COPY sample_data/ ./sample_data/

# The intelligence corpus is a VERSIONED INPUT, not a build artefact — see the
# note in .gitignore. Baking it in means the container answers offline and
# names the catalogue version it answered from.
COPY data/ ./data/

COPY --from=console /build/dist ./frontend/dist

# Run as nobody. Nothing here needs to write to the image, and a collector that
# reaches the internet should not be doing so as root.
RUN useradd --system --create-home --uid 10001 skopos \
    && chown -R skopos:skopos /app
USER skopos

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
