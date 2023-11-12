FROM node:lts-alpine
LABEL maintainer="thibaut severac <thib3113@gmail.com>"

RUN apk upgrade && \
    apk add --no-cache python3 py3-pip make

RUN npm install -g npm && \
    npm install -g pnpm

WORKDIR /app

COPY ./docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
RUN ln -s usr/local/bin/docker-entrypoint.sh /

RUN mkdir -p /tmp/src

COPY . /tmp/src

RUN cd /tmp/src && \
    pnpm install --frozen-lockfile && \
    pnpm build && \
    mv build /app && \
    mv package.json /app

RUN rm -Rf /tmp/src
RUN pnpm install -P

RUN apk del python3 py3-pip make

#HEALTHCHECK --interval=1m --timeout=3s \
#  CMD yarn run healthCheck || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
