FROM python:3.10@sha256:fd0fa50d997eb56ce560c6e5ca6a1f5cf8fdff87572a16ac07fb1f5ca01eb608

WORKDIR /app

ADD credsweeper /app/credsweeper

COPY pyproject.toml /app/
COPY README.md /app/

RUN pip install .

COPY entrypoint.sh /entrypoint.sh

RUN chmod a+x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
