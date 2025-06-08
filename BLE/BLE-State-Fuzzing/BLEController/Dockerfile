FROM python:2.7.17-slim-buster

ENV HOME /root/
ENV TERM xterm-256color
ENV RUNNING_DOCKER ON

WORKDIR $HOME

ADD requirements.sh $HOME
ADD wifi/ wifi/
ADD bluetooth/ bluetooth/

RUN apt-get update && apt-get install sudo -y && ./requirements.sh

CMD tail -f /dev/null