FROM ruby:3.3-alpine

RUN apk add --no-cache git

COPY lib/ /sentinel/lib/
COPY bot/ /sentinel/bot/
COPY bin/ /sentinel/bin/

WORKDIR /sentinel

# The bot is invoked via: ruby bot/scanner_bot.rb --pattern rotate
# Railway cron will handle scheduling
CMD ["ruby", "bot/scanner_bot.rb", "--pattern", "rotate"]
