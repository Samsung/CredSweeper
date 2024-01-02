FROM python:3.9

WORKDIR /app

ADD credsweeper /app/credsweeper

COPY setup.py /app/
COPY README.md /app/

RUN pip install .

COPY entrypoint.sh /entrypoint.sh

RUN chmod a+x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
