FROM python:3.10-slim
ARG VERSION

RUN pip3 install secscanner2junit==$VERSION

WORKDIR /tmp
ENTRYPOINT ["ss2ju"]
