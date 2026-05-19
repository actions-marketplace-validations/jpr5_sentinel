FROM ruby:3.3-alpine

RUN apk add --no-cache git
RUN gem install sinatra --no-doc

COPY lib/ /sentinel/lib/
COPY bot/ /sentinel/bot/
COPY bin/ /sentinel/bin/

RUN mkdir -p /sentinel/data

WORKDIR /sentinel

# Run a queue-mode scan and exit. Railway cron or GitHub Actions triggers the container.
CMD ["ruby", "-Ilib", "-Ibot", "bot/scanner_bot.rb", "--queue", "--limit", "100", "--pattern", "rotate"]
