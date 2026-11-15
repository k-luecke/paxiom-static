# Zero-dependency MCP stdio server image for Paxiom Receipts (Glama / MCP inspection)
FROM node:22-alpine

WORKDIR /app

COPY standards/receipts/v0/package.json ./package.json
COPY standards/receipts/v0/paxiom.receipt.v0.schema.json ./paxiom.receipt.v0.schema.json
COPY standards/receipts/v0/src ./src
COPY standards/receipts/v0/mcp ./mcp
COPY standards/receipts/v0/bin ./bin

ENV NODE_ENV=production

CMD ["node", "/app/mcp/server.mjs"]
