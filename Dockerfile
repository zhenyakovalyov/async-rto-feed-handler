FROM python:3.12-slim-bullseye as base

# Set environment variables.
ENV PYTHONDONTWRITEBYTECODE 1 
ENV PYTHONUNBUFFERED 1

# Set the working directory.
WORKDIR /app

FROM base as builder

ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.8.3

RUN pip install --upgrade pip
RUN pip install "poetry==$POETRY_VERSION"
RUN python -m venv /venv

# Copy only the relevant files to install dependencies.
COPY pyproject.toml ./
COPY poetry.lock ./

# Install dependencies
# This installs feedhandler as the library
RUN poetry -f requirements.txt | /venv/bin/pip install -r /dev/stdin

# Copy the content of the local src directory to the working directory.
COPY . .

RUN poetry build 
RUN /venv/bin/pip install dist/*.whl

FROM base as final

COPY --from=builder /venv /venv

COPY demo.py .
COPY docker-entrypoint.sh .

ENTRYPOINT ["./docker-entrypoint.sh"]