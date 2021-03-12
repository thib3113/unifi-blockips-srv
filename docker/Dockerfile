FROM node:lts-alpine
LABEL maintainer="thibaut severac <thib3113@gmail.com>"

RUN apk add --no-cache yarn

#add node_modules in cache
VOLUME /app/node_modules

WORKDIR /app

COPY ./docker/entrypoint.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
RUN ln -s usr/local/bin/docker-entrypoint.sh /

RUN mkdir -p ./tmp/ && \
    . ./tmp && \
    cd ./tmp && \
    ls -alh && \
    yarn install --production=false && \
    yarn build && \
    mv build /app && \
    mv package.json /app
    
RUN rm -Rf /tmp/src
RUN yarn install --prod


#HEALTHCHECK --interval=1m --timeout=3s \
#  CMD yarn run healthCheck || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
