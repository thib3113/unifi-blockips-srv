FROM node:lts-alpine as builder

RUN apk add --no-cache build-base python3 py3-pip make jq

RUN npm install -g npm && \
    npm install -g pnpm

WORKDIR /app

RUN mkdir -p /tmp/src

COPY . /tmp/src

RUN cd /tmp/src && \
    echo "node-linker=hoisted" >> .npmrc &&\
    pnpm install --frozen-lockfile && \
    pnpm build && \
    pnpm prune --prod && \
    for file in $(jq -r '.files[]' package.json); do cp -R $file /app/$file; done && \
    cp package.json /app/ && \
    cp -R node_modules /app/

RUN rm -Rf /tmp/src

FROM node:lts-alpine
LABEL maintainer="thibaut severac <thib3113@gmail.com>"
WORKDIR /app

COPY --from=builder /app .

RUN npm install -g npm

COPY ./docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
RUN ln -s usr/local/bin/docker-entrypoint.sh /

ENTRYPOINT ["docker-entrypoint.sh"]
