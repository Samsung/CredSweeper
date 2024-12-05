FROM python:3.8

WORKDIR /user

ADD tests/samples /user

RUN pip install credsweeper


ENTRYPOINT ["credsweeper", "--path", "/user"]
