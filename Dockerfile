FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN mkdir -p /app/data && chown -R node:node /app

EXPOSE 3000

USER node

ENV DB_PATH=/app/data/visitors.db

CMD ["node", "server.js"]
