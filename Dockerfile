FROM ruby:3.3-alpine

RUN apk add --no-cache git

RUN adduser -D -h /scanner scanner

COPY lib/ /scanner/lib/
COPY bin/ /scanner/bin/
COPY action/annotate.rb /scanner/action/annotate.rb

RUN chmod +x /scanner/bin/sentinel

USER scanner
WORKDIR /scanner

ENTRYPOINT ["ruby", "/scanner/action/annotate.rb"]
