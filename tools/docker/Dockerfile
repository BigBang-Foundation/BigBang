FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive
ENV HOME=/home/big

VOLUME ["${HOME}"]
COPY entrypoint.sh /sbin/
RUN chmod 755 /sbin/entrypoint.sh
COPY build/src/bigbang/bigbang* /usr/bin/
COPY bigbang.conf /bigbang.conf
EXPOSE 9901 9902 9903 9904 9905
ENTRYPOINT ["/sbin/entrypoint.sh"]
CMD ["bigbang"]
