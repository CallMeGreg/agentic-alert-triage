FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

COPY --chown=node:node index.js config.yml app.yml ./
COPY --chown=node:node scripts ./scripts

USER node
EXPOSE 3000

CMD ["npm", "start"]
