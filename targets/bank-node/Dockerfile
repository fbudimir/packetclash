FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install --production && npm install -g pm2

COPY . .

ENV WORKERS=1

CMD ["sh", "-c", "pm2-runtime start app.js -i $WORKERS"]