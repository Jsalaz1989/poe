# pull official base image
FROM python:3.8.3-alpine

# set work directory
WORKDIR /usr/src/app

# activate virtual environment
ENV VIRTUAL_ENV=/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install psycopg2 dependencies
RUN apk update \
    && apk add postgresql-dev gcc python3-dev musl-dev

# install cryptography dependencies
RUN apk add --no-cache \
        libressl-dev \
        libffi-dev

# install dependencies
COPY ./requirements.txt .
COPY ./django-polls-0.1.tar.gz .
RUN pip install --upgrade pip && pip install -r requirements.txt && pip install django-polls-0.1.tar.gz

# copy entrypoint.sh
COPY ./entrypoint.sh .

# copy project
COPY . .

# run entrypoint.sh
ENTRYPOINT ["/usr/src/app/entrypoint.sh"]