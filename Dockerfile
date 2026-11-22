FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

ENV MCP_OAUTH_STATE_FILE=/data/oauth-state.json

CMD ["node", "dist/index.js"]
