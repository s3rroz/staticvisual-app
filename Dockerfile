FROM node:20-alpine
WORKDIR /app
COPY server ./server
COPY site ./public
ENV NODE_ENV=production
EXPOSE 8000
CMD ["node", "server/index.js"]
