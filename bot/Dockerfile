FROM ruby:3.3-alpine

RUN apk add --no-cache git
RUN gem install sinatra --no-doc

COPY lib/ /sentinel/lib/
COPY bot/ /sentinel/bot/
COPY bin/ /sentinel/bin/

RUN mkdir -p /sentinel/data

WORKDIR /sentinel

# Default: sleep forever. The bot runs via Railway cron trigger, not on container start.
# This prevents accidental live scans on every deploy.
CMD ["sleep", "infinity"]
