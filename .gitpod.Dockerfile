FROM gitpod/workspace-python-3.10

USER gitpod

RUN curl -sSL https://install.python-poetry.org/ | python -

RUN poetry --version
