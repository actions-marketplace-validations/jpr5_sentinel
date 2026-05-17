FROM ruby:3.3-alpine

RUN apk add --no-cache git
RUN gem install sinatra --no-doc

COPY lib/ /sentinel/lib/
COPY bot/ /sentinel/bot/
COPY bin/ /sentinel/bin/

WORKDIR /sentinel

# Default: run the bot. Override CMD for the web handler.
CMD ["ruby", "bot/scanner_bot.rb", "--pattern", "rotate"]
