FROM ruby:3.3-alpine

RUN apk add --no-cache git

COPY lib/ /scanner/lib/
COPY bin/ /scanner/bin/
COPY action/annotate.rb /scanner/action/annotate.rb

RUN chmod +x /scanner/bin/gh-workflow-scanner /scanner/action/annotate.rb

ENTRYPOINT ["ruby", "/scanner/action/annotate.rb"]
