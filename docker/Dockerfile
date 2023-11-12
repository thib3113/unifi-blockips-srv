FROM node:lts-alpine as builder

RUN apk add --no-cache build-base python3 py3-pip make

RUN npm install -g npm && \
    npm install -g pnpm

WORKDIR /app

RUN mkdir -p /tmp/src

COPY . /tmp/src

RUN cd /tmp/src && \
    pnpm install --frozen-lockfile && \
    pnpm build && \
    mv build /app && \
    mv package.json /app

RUN rm -Rf /tmp/src

FROM node:lts-alpine
LABEL maintainer="thibaut severac <thib3113@gmail.com>"
WORKDIR /app

RUN apk add --no-cache build-base python3 py3-pip make

COPY --from=builder /app .

RUN npm install -g npm && \
    npm install -g pnpm
RUN pnpm install -P

RUN npm remove -g pnpm yarn &&\
    npm cache clean --force &&\
    apk del build-base python3 py3-pip make

COPY ./docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
RUN ln -s usr/local/bin/docker-entrypoint.sh /

ENTRYPOINT ["docker-entrypoint.sh"]
