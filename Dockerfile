FROM golang:1.12-alpine as build-env
ADD . /go/src/github.com/entropyx/k8-letsencrypt
WORKDIR /go/src/github.com/entropyx/k8-letsencrypt
RUN apk add --update git
RUN apk add ca-certificates wget && update-ca-certificates
RUN GO111MODULE=on go build -o lek8

FROM alpine
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN apk --no-cache add tzdata
COPY --from=build-env /go/src/github.com/entropyx/k8-letsencrypt/lek8 /usr/local/bin
CMD lek8
