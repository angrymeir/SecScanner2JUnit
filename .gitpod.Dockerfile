FROM gitpod/workspace-full:latest

USER gitpod

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -

RUN poetry --version
