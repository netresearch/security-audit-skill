# Infrastructure-as-Code Security

Infrastructure-as-Code (IaC) defines cloud and container infrastructure in version-controlled configuration files. Security misconfigurations in these files are deployed automatically and at scale, making IaC a critical audit surface. This reference covers Dockerfiles, Docker Compose, Kubernetes manifests, and Terraform configurations.

---

## Dockerfile Security

### Running as Root

By default, Docker containers run as `root` (UID 0). If an attacker escapes the application but remains inside the container, they have full root privileges, making further exploitation and container escape significantly easier.

```dockerfile
# VULNERABLE: No USER directive — container runs as root
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8000
CMD ["python", "app.py"]
```

```dockerfile
# VULNERABLE: Explicit USER root
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
USER root
EXPOSE 8000
CMD ["python", "app.py"]
```

```dockerfile
# SECURE: Create a non-root user and switch to it
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user with specific UID/GID
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/false --create-home appuser

COPY --chown=appuser:appgroup . .
USER appuser
EXPOSE 8000
CMD ["python", "app.py"]
```

### Detection Patterns

A pure line-based regex cannot reliably detect "no USER directive anywhere in the file" because that is a whole-file property. Prefer whole-file checks:

```bash
# Dockerfiles missing USER directive — flag any Dockerfile that never declares USER.
# Run per file; exit status 1 (no match) means USER is missing.
for f in $(find . -name 'Dockerfile*' -type f); do
  grep -qE '^\s*USER\b' "$f" || echo "MISSING USER: $f"
done

# Explicit root user
grep -rnE '^\s*USER[[:space:]]+root\b' --include='Dockerfile*' .

# USER appearing after the last CMD/ENTRYPOINT (too late to apply).
# Use awk so we can reason line-by-line across the whole file.
awk '
  /^[[:space:]]*(CMD|ENTRYPOINT)\b/ { last_exec = NR }
  /^[[:space:]]*USER\b/              { last_user = NR }
  END { if (last_exec && last_user && last_user > last_exec) print FILENAME": USER after CMD/ENTRYPOINT" }
' Dockerfile*
```

If you use a PCRE-capable scanner (`grep -P`, ripgrep, Semgrep), an equivalent whole-file negative-lookahead is:

```
(?ms)\A(?!.*^\s*USER\b).*^\s*FROM\b.*\z
```

### Secrets in Image Layers

Every `COPY`, `ADD`, `RUN`, and `ARG` instruction creates a layer that persists in the image history. Secrets placed into layers can be extracted even if a later layer deletes them.

```dockerfile
# VULNERABLE: Copying .env file into the image
FROM node:20-alpine
WORKDIR /app
COPY . .
# .env with DB_PASSWORD, API_KEY, etc. is now baked into a layer
RUN npm install
CMD ["node", "server.js"]
```

```dockerfile
# VULNERABLE: Build argument containing a secret
FROM node:20-alpine
ARG DATABASE_PASSWORD
# ARG values are visible in `docker history`
ENV DB_PASS=${DATABASE_PASSWORD}
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
```

```dockerfile
# VULNERABLE: Secret in RUN command
FROM alpine:3.19
RUN curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret-token" \
    https://api.example.com/config > /app/config.json
```

```dockerfile
# SECURE: Use BuildKit secret mounts (secrets never persist in layers)
# syntax=docker/dockerfile:1
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .

# Mount secret at build time — it is available only during this RUN step
# and is never written to any image layer
RUN --mount=type=secret,id=db_password \
    DB_PASS=$(cat /run/secrets/db_password) && \
    node setup-db.js

CMD ["node", "server.js"]
# Build with: docker buildx build --secret id=db_password,src=./db_password.txt .
```

```dockerfile
# SECURE: Use .dockerignore to prevent secrets from entering the build context
# .dockerignore
.env
.env.*
*.pem
*.key
credentials.json
secrets/
```

### Detection Patterns

```
# .env file copied into image
COPY\s+.*\.env
ADD\s+.*\.env

# Secrets in ARG instructions
ARG\s+(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIALS)

# Secrets in RUN commands
RUN\s.*curl\s.*(-H\s+["']Authorization:|--header\s.*Bearer)
RUN\s.*(PASSWORD|SECRET|TOKEN|API_KEY)=
```

### Unsigned and Unversioned Base Images

Using a bare image name without a tag or digest means Docker pulls `latest`, which is mutable. An attacker who compromises the registry can push a malicious `latest` tag, or a legitimate update may introduce breaking changes or new vulnerabilities.

```dockerfile
# VULNERABLE: No tag — implicitly pulls :latest, which is mutable
FROM ubuntu
FROM python
FROM node
```

```dockerfile
# BETTER: Pinned to a specific version tag
FROM ubuntu:24.04
FROM python:3.12-slim
FROM node:20-alpine
```

```dockerfile
# SECURE: Pinned to an immutable content-addressable digest
FROM python:3.12-slim@sha256:1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
```

### Detection Patterns

```
# Base image without tag or digest
^FROM\s+[a-z][a-z0-9._-]+(/[a-z][a-z0-9._-]+)?\s*$

# Base image using :latest explicitly
^FROM\s+\S+:latest
```

### ADD vs COPY Security Implications

`ADD` has two capabilities beyond `COPY`: it can fetch remote URLs and auto-extract compressed archives (tar, gzip, bzip2, xz). These features expand the attack surface.

- **Remote URL fetching**: `ADD` downloads files without checksum verification, enabling man-in-the-middle attacks.
- **Auto-extraction**: Maliciously crafted tar archives can exploit path traversal (e.g., `../../etc/passwd`) or zip bombs.

```dockerfile
# VULNERABLE: ADD fetches a remote URL with no integrity verification
FROM alpine:3.19
ADD https://example.com/app.tar.gz /app/
RUN cd /app && tar -xzf app.tar.gz
```

```dockerfile
# SECURE: Use COPY for local files (no auto-extraction, no remote fetch)
FROM alpine:3.19
COPY app/ /app/
```

```dockerfile
# SECURE: If you need to download a remote file, use RUN with checksum verification (SHA-256)
FROM alpine:3.19
RUN wget -O /tmp/app.tar.gz https://example.com/app.tar.gz && \
    echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /tmp/app.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/app.tar.gz -C /app/ && \
    rm /tmp/app.tar.gz
```

### Detection Patterns

```
# ADD instruction (flag for review, prefer COPY)
^ADD\s

# ADD fetching remote URL
^ADD\s+https?://
```

### Multi-Stage Build Best Practices

Multi-stage builds allow you to use full build toolchains in earlier stages, then copy only the compiled artifacts into a minimal final image. This reduces the attack surface by excluding compilers, package managers, source code, and build-time secrets from the production image.

```dockerfile
# VULNERABLE: Single-stage build includes build tools, source, and dev dependencies
FROM node:20
WORKDIR /app
COPY . .
RUN npm install
RUN npm run build
EXPOSE 3000
CMD ["node", "dist/server.js"]
# Final image contains: npm, node_modules (dev+prod), source code, build tools
```

```dockerfile
# SECURE: Multi-stage build — final image contains only production artifacts
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS production
WORKDIR /app
# Copy only production dependencies and compiled output
COPY --from=builder /app/package*.json ./
RUN npm ci --production && npm cache clean --force
COPY --from=builder /app/dist ./dist

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
EXPOSE 3000
CMD ["node", "dist/server.js"]
# Final image contains: node runtime, production node_modules, compiled dist/ only
```

---

## Docker Compose Security

### Privileged Containers

The `privileged: true` flag disables almost all container isolation. A privileged container has full access to the host's devices, can load kernel modules, and can trivially escape to the host.

```yaml
# VULNERABLE: privileged grants near-full host access
version: "3.9"
services:
  app:
    image: myapp:latest
    privileged: true
    ports:
      - "8080:8080"
```

```yaml
# SECURE: Drop all capabilities and add back only what is needed
version: "3.9"
services:
  app:
    image: myapp:latest
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only if binding to ports < 1024
    security_opt:
      - no-new-privileges:true
    read_only: true
    ports:
      - "8080:8080"
```

### Detection Patterns

```
# Privileged flag
privileged:\s*true

# Dangerous capabilities
cap_add:.*SYS_ADMIN
cap_add:.*SYS_PTRACE
cap_add:.*ALL
```

### Sensitive Host Mounts

Mounting the Docker socket or sensitive host directories into a container allows full host compromise from within the container.

```yaml
# VULNERABLE: Docker socket mount — container can control the Docker daemon
version: "3.9"
services:
  monitoring:
    image: monitoring-tool:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  # VULNERABLE: Host root filesystem mounted
  backup:
    image: backup-tool:latest
    volumes:
      - /:/host-root

  # VULNERABLE: Host /etc mounted — container can modify host config
  config-editor:
    image: config-tool:latest
    volumes:
      - /etc:/host-etc
```

```yaml
# SECURE: Mount only the specific directories needed, read-only where possible
version: "3.9"
services:
  app:
    image: myapp:latest
    volumes:
      - app-data:/app/data              # Named volume (managed by Docker)
      - ./config/app.conf:/app/app.conf:ro  # Single config file, read-only
    read_only: true
    tmpfs:
      - /tmp
      - /var/run

volumes:
  app-data:
```

### Detection Patterns

```
# Docker socket mount
/var/run/docker\.sock

# Root filesystem mount
volumes:.*[:-]\s*/:/

# Sensitive directory mounts
volumes:.*[:-]\s*/etc[:/]
volumes:.*[:-]\s*/proc[:/]
volumes:.*[:-]\s*/sys[:/]
volumes:.*[:-]\s*/dev[:/]
```

### Unnecessary Port Exposure

`ports:` publishes a port on the host interface, making it reachable from the network. `expose:` only makes a port available to linked services within the Docker network.

```yaml
# VULNERABLE: Database port published to host — accessible from network
version: "3.9"
services:
  app:
    image: myapp:latest
    ports:
      - "8080:8080"  # Intended: public-facing app

  db:
    image: postgres:16
    ports:
      - "5432:5432"  # VULNERABLE: Database directly reachable from network

  redis:
    image: redis:7
    ports:
      - "6379:6379"  # VULNERABLE: Cache reachable from network (no auth by default)
```

```yaml
# SECURE: Only expose what must be publicly reachable
version: "3.9"
services:
  app:
    image: myapp:latest
    ports:
      - "127.0.0.1:8080:8080"  # Bind to localhost only if behind reverse proxy
    networks:
      - frontend
      - backend

  db:
    image: postgres:16
    expose:
      - "5432"  # Only reachable within Docker network
    networks:
      - backend

  redis:
    image: redis:7
    expose:
      - "6379"  # Only reachable within Docker network
    networks:
      - backend

networks:
  frontend:
  backend:
    internal: true  # No external access at all
```

### Detection Patterns

```
# Database ports published to host
ports:.*5432
ports:.*3306
ports:.*27017
ports:.*6379

# Port bound to all interfaces (0.0.0.0, or missing host binding)
ports:\s*-\s*"?\d+:\d+"?
# vs safe: ports: - "127.0.0.1:8080:8080"
```

### Missing Resource Limits

Without resource limits, a compromised or misbehaving container can consume all host CPU and memory, causing denial of service to other containers and the host itself.

```yaml
# VULNERABLE: No resource limits
version: "3.9"
services:
  app:
    image: myapp:latest
```

```yaml
# SECURE: Resource limits configured
version: "3.9"
services:
  app:
    image: myapp:latest
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
        reservations:
          cpus: "0.25"
          memory: 128M
    # For docker-compose v2 compatibility:
    mem_limit: 512m
    cpus: 1.0
```

### Environment Variable Secrets in Plaintext

Secrets defined directly in `docker-compose.yml` or `.env` files checked into version control are visible to anyone with repository access.

```yaml
# VULNERABLE: Plaintext secrets in compose file
version: "3.9"
services:
  app:
    image: myapp:latest
    environment:
      - DATABASE_PASSWORD=SuperSecret123!
      - API_KEY=sk-live-abc123def456
      - JWT_SECRET=my-jwt-signing-key
```

```yaml
# SECURE: Use Docker secrets (Swarm mode) or external secret management
version: "3.9"
services:
  app:
    image: myapp:latest
    environment:
      - DATABASE_HOST=db
      - DATABASE_NAME=myapp
    secrets:
      - db_password
      - api_key

secrets:
  db_password:
    external: true   # Managed outside of compose, e.g., via `docker secret create`
  api_key:
    external: true
```

### Detection Patterns

```
# Plaintext secrets in environment
environment:.*PASSWORD=
environment:.*SECRET=
environment:.*API_KEY=
environment:.*TOKEN=
environment:.*PRIVATE_KEY=

# Inline secret values
environment:\s*-\s*(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*\S+
```

---

## Kubernetes Security

### Overly Permissive RBAC

Kubernetes Role-Based Access Control (RBAC) restricts what users and service accounts can do. Overly broad roles, especially `cluster-admin` bindings and wildcard permissions, allow any compromised workload to take over the entire cluster.

```yaml
# VULNERABLE: Binding a service account to cluster-admin
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin-binding
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin    # Full unrestricted cluster access
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# VULNERABLE: Wildcard verbs and resources
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: overly-permissive
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]         # Can do anything to any resource in any API group
```

```yaml
# SECURE: Least-privilege Role scoped to a specific namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: myapp
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
    resourceNames: ["app-config"]   # Restrict to specific named resources
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: myapp
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: myapp
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
```

### Detection Patterns

```
# ClusterRoleBinding to cluster-admin
kind:\s*ClusterRoleBinding[\s\S]*?name:\s*cluster-admin

# Wildcard permissions
verbs:\s*\[?"?\*"?\]?
resources:\s*\[?"?\*"?\]?
apiGroups:\s*\[?"?\*"?\]?
```

### Missing NetworkPolicy

By default, all pods in a Kubernetes cluster can communicate with all other pods across all namespaces. Without NetworkPolicy, a compromised pod can probe, attack, and pivot to any other workload in the cluster.

```yaml
# VULNERABLE (by omission): No NetworkPolicy exists
# All pods can reach all other pods on all ports across all namespaces
# — there is no manifest to show; the absence IS the vulnerability
```

```yaml
# SECURE: Default-deny ingress policy — pods must be explicitly allowed
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: myapp
spec:
  podSelector: {}   # Applies to all pods in the namespace
  policyTypes:
    - Ingress
    # No ingress rules = deny all inbound traffic
---
# SECURE: Allow only specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: myapp
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
---
# SECURE: Default-deny egress — prevent data exfiltration
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: myapp
spec:
  podSelector: {}
  policyTypes:
    - Egress
    # No egress rules = deny all outbound traffic
```

### Pod Security

Pods should run as non-root, with a read-only root filesystem, and with explicit security contexts. Missing security contexts leave containers with default (often overly permissive) settings.

```yaml
# VULNERABLE: Running as root with no security context
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
    - name: app
      image: myapp:latest
# No securityContext at all — container runs as root by default
```

```yaml
# VULNERABLE: Explicitly running as root with dangerous settings
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-pod
spec:
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        runAsUser: 0                    # Root
        privileged: true                # Full host access
        allowPrivilegeEscalation: true  # Can gain additional privileges
```

```yaml
# SECURE: Hardened pod security context
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true          # Fail if image tries to run as UID 0
    runAsUser: 1001
    runAsGroup: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault      # Apply default seccomp filtering
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true   # Prevent writes to container filesystem
        capabilities:
          drop:
            - ALL                       # Drop all Linux capabilities
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
  volumes:
    - name: tmp
      emptyDir: {}
    - name: cache
      emptyDir: {}
```

### Detection Patterns

```
# Running as root
runAsUser:\s*0

# Missing runAsNonRoot
# (Absence of runAsNonRoot in a pod spec is the vulnerability)

# Privileged container
privileged:\s*true

# Privilege escalation allowed
allowPrivilegeEscalation:\s*true
```

### Host Namespace Sharing

`hostNetwork`, `hostPID`, and `hostIPC` break container isolation by sharing the host's network stack, process tree, or inter-process communication namespace with the container.

```yaml
# VULNERABLE: Host namespace sharing
apiVersion: v1
kind: Pod
metadata:
  name: host-namespace-pod
spec:
  hostNetwork: true   # Pod shares the host's network — can bind to host ports,
                       # see all host network traffic, access localhost services
  hostPID: true        # Pod can see all host processes — enables ptrace attacks,
                       # signals to host processes, /proc filesystem access
  hostIPC: true        # Pod shares host IPC namespace — can access host shared memory
  containers:
    - name: app
      image: myapp:latest
```

```yaml
# SECURE: No host namespace sharing (these are the defaults, shown for clarity)
apiVersion: v1
kind: Pod
metadata:
  name: isolated-pod
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        runAsNonRoot: true
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
```

### Detection Patterns

```
# Host namespace sharing
hostNetwork:\s*true
hostPID:\s*true
hostIPC:\s*true
```

### Missing Resource Requests and Limits

Without resource requests and limits, a single pod can consume all available node resources, starving other workloads (noisy neighbor problem) or enabling denial-of-service attacks.

```yaml
# VULNERABLE: No resource constraints
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
        - name: app
          image: myapp:latest
          # No resources block — unbounded CPU and memory usage
```

```yaml
# SECURE: Resource requests and limits defined
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
        - name: app
          image: myapp:latest
          resources:
            requests:
              cpu: "100m"       # Guaranteed minimum
              memory: "128Mi"
            limits:
              cpu: "500m"       # Hard ceiling
              memory: "256Mi"   # OOMKilled if exceeded
```

### Secrets in Plaintext

Kubernetes Secrets are base64-encoded, not encrypted. Anyone with access to the etcd datastore or the API server can read them. Use external secret management or sealed-secrets for production.

```yaml
# VULNERABLE: Secret with base64-encoded values (trivially decodable)
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  db-password: c3VwZXJTZWNyZXQxMjM=    # echo -n 'superSecret123' | base64
  api-key: c2stbGl2ZS1hYmMxMjM=         # echo -n 'sk-live-abc123' | base64
```

```yaml
# VULNERABLE: Secret values hardcoded in pod spec
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: myapp:latest
      env:
        - name: DB_PASSWORD
          value: "superSecret123"   # Plaintext in the manifest
```

```yaml
# SECURE: Use external-secrets-operator to sync from a vault
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: myapp
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: app-secrets
  data:
    - secretKey: db-password
      remoteRef:
        key: myapp/production/db-password
    - secretKey: api-key
      remoteRef:
        key: myapp/production/api-key
```

```yaml
# SECURE: Use sealed-secrets (encrypted, safe to store in Git)
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: app-secrets
  namespace: myapp
spec:
  encryptedData:
    db-password: AgBy8hCi...encrypted...==
    api-key: AgCtr4Qp...encrypted...==
```

### Detection Patterns

```
# Hardcoded secret values in pod specs
env:[\s\S]*?name:\s*(PASSWORD|SECRET|API_KEY|TOKEN)[\s\S]*?value:\s*"[^"]+

# Base64-encoded secrets in Secret manifests (all k8s Secrets use this, flag for review)
kind:\s*Secret[\s\S]*?data:[\s\S]*?:\s*[A-Za-z0-9+/]+=*

# Secrets not using external-secrets or sealed-secrets
kind:\s*Secret[\s\S]*?type:\s*Opaque
```

---

## Terraform Security

### Public S3 Buckets

S3 buckets with public ACLs or policies expose data to the internet. This is one of the most common causes of large-scale data breaches in cloud environments.

```hcl
# VULNERABLE: Public ACL on S3 bucket
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"    # Anyone on the internet can read bucket contents
}
```

```hcl
# VULNERABLE: Bucket policy allowing public access
resource "aws_s3_bucket_policy" "public" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"          # Any AWS principal, including anonymous
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })
}
```

```hcl
# SECURE: Private bucket with public access block
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

### Detection Patterns

```
# Public S3 ACLs
acl\s*=\s*"public-read"
acl\s*=\s*"public-read-write"

# Wildcard principal in bucket policies
Principal\s*=\s*"\*"
"Principal":\s*"\*"

# Missing public access block (absence of aws_s3_bucket_public_access_block for each bucket)
```

### Security Groups with Open Ingress

Security groups with `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6) ingress rules expose services to the entire internet. This is especially dangerous for management ports like SSH (22), RDP (3389), and databases.

```hcl
# VULNERABLE: SSH open to the world
resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]    # Any IP can SSH in
  }

  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]    # All ports open to all IPs
  }
}
```

```hcl
# SECURE: Restrict ingress to known CIDR ranges and specific ports
resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application security group"
  vpc_id      = aws_vpc.main.id

  # No inline rules — use separate aws_security_group_rule resources
  # for better modularity and audit trail
}

resource "aws_security_group_rule" "app_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.app.id
  source_security_group_id = aws_security_group.alb.id  # Only from the load balancer
}

resource "aws_security_group_rule" "ssh_bastion" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = aws_security_group.app.id
  cidr_blocks       = ["10.0.0.0/24"]   # Only from bastion subnet
}
```

### Detection Patterns

```
# Open ingress to all IPs
cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"
ipv6_cidr_blocks\s*=\s*\[?"::/0"

# All ports open
from_port\s*=\s*0[\s\S]*?to_port\s*=\s*0[\s\S]*?protocol\s*=\s*"-1"

# Sensitive ports open (SSH, RDP, databases)
(from_port\s*=\s*(22|3389|3306|5432|27017|6379))[\s\S]*?cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"
```

### Unencrypted Storage and Databases

Data at rest should always be encrypted. Unencrypted EBS volumes, RDS instances, and S3 buckets leave data exposed if storage media is compromised or improperly decommissioned.

```hcl
# VULNERABLE: Unencrypted RDS instance
resource "aws_db_instance" "main" {
  identifier     = "production-db"
  engine         = "postgres"
  engine_version = "16.1"
  instance_class = "db.r6g.large"
  allocated_storage = 100
  # storage_encrypted not set — defaults to false
  # no kms_key_id specified

  username = "admin"
  password = "hardcoded-password-123"   # Also a hardcoded credential
}
```

```hcl
# VULNERABLE: Unencrypted EBS volume
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  # encrypted not set — defaults to false
}
```

```hcl
# SECURE: Encrypted RDS with KMS
resource "aws_db_instance" "main" {
  identifier     = "production-db"
  engine         = "postgres"
  engine_version = "16.1"
  instance_class = "db.r6g.large"
  allocated_storage = 100

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  # Password from Secrets Manager, not hardcoded
  username                    = "admin"
  manage_master_user_password = true   # AWS manages the password in Secrets Manager

  # Additional hardening
  deletion_protection   = true
  skip_final_snapshot   = false
  multi_az              = true
  backup_retention_period = 30
  iam_database_authentication_enabled = true
}

# SECURE: Encrypted EBS with KMS
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn

  tags = {
    Name = "encrypted-data-volume"
  }
}
```

### Detection Patterns

```
# Unencrypted RDS
resource\s+"aws_db_instance"(?![\s\S]*?storage_encrypted\s*=\s*true)

# Unencrypted EBS
resource\s+"aws_ebs_volume"(?![\s\S]*?encrypted\s*=\s*true)

# Unencrypted S3
# (Absence of aws_s3_bucket_server_side_encryption_configuration for each bucket)

# Hardcoded passwords in Terraform
password\s*=\s*"[^"]*"
secret\s*=\s*"[^"]*"
```

### Missing Logging and Monitoring

Without CloudTrail, VPC Flow Logs, and other monitoring, you have no visibility into who is accessing your infrastructure, making breach detection and forensic analysis impossible.

```hcl
# VULNERABLE: No CloudTrail configured
# (Absence of aws_cloudtrail resource means no API audit logging)

# VULNERABLE: VPC without flow logs
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  # No flow logs — no visibility into network traffic
}
```

```hcl
# SECURE: CloudTrail with S3 logging and log file validation
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true    # Detect tampering with log files
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]    # Log all S3 data events
    }
  }
}

# SECURE: VPC Flow Logs
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow.arn
  traffic_type    = "ALL"      # Log accepted AND rejected traffic
  vpc_id          = aws_vpc.main.id

  tags = {
    Name = "vpc-flow-log"
  }
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 365    # Retain for compliance
  kms_key_id        = aws_kms_key.logs.arn
}
```

### Detection Patterns

```bash
# VPC without flow logs — inventory aws_vpc and aws_flow_log, flag any VPC without
# a matching aws_flow_log pointing at it. A simple resource-name regex cannot
# decide this on its own, because flow logs live in a separate resource.
# Use a policy tool (Checkov CKV_AWS_11, tfsec aws-vpc-no-public-egress-sgr,
# Terrascan AC_AWS_0059) or a module inventory instead.

# CloudTrail missing log file validation
grep -rnE 'enable_log_file_validation[[:space:]]*=[[:space:]]*false' --include='*.tf' .

# CloudTrail not multi-region
grep -rnE 'is_multi_region_trail[[:space:]]*=[[:space:]]*false' --include='*.tf' .
```

### Hardcoded Credentials in .tf Files

Credentials hardcoded in Terraform files end up in state files, version control, and CI/CD logs. Terraform state often contains the plaintext values of all resources, including secrets.

```hcl
# VULNERABLE: Hardcoded AWS credentials
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# VULNERABLE: Hardcoded database password
resource "aws_db_instance" "main" {
  username = "admin"
  password = "ProductionP@ssw0rd!"
}

# VULNERABLE: Hardcoded API token in user_data
resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export API_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    export DD_API_KEY="abcdef1234567890abcdef1234567890"
  EOF
}
```

```hcl
# SECURE: Use environment variables or IAM roles for provider auth
provider "aws" {
  region = "us-east-1"
  # Credentials from environment variables, instance profile, or SSO
  # AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY set in CI/CD environment
  # Or use assume_role for cross-account access
  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/TerraformDeployRole"
  }
}

# SECURE: Use variables with sensitive flag (never in .tf files directly)
variable "db_password" {
  type      = string
  sensitive = true   # Prevents display in plan/apply output
  # Value provided via TF_VAR_db_password env var or .tfvars (not in VCS)
}

resource "aws_db_instance" "main" {
  username = "admin"
  password = var.db_password
}

# SECURE: Use AWS Secrets Manager data source
data "aws_secretsmanager_secret_version" "api_token" {
  secret_id = "myapp/api-token"
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    api_token = data.aws_secretsmanager_secret_version.api_token.secret_string
  })
}
```

### Detection Patterns

```
# AWS access keys hardcoded
access_key\s*=\s*"AKIA[A-Z0-9]{16}"
secret_key\s*=\s*"[A-Za-z0-9/+=]{40}"

# Generic hardcoded credentials
password\s*=\s*"[^"]{4,}"
secret\s*=\s*"[^"]{4,}"
api_key\s*=\s*"[^"]{4,}"
token\s*=\s*"[^"]{4,}"

# GitHub tokens
ghp_[A-Za-z0-9]{36}
github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}

# Sensitive data in user_data
user_data\s*=.*<<[\s\S]*?(PASSWORD|SECRET|TOKEN|API_KEY)
```

---

## Prevention Checklist

### Dockerfile

- [ ] All images use a non-root `USER` directive before `CMD`/`ENTRYPOINT`
- [ ] `.dockerignore` excludes `.env`, `*.pem`, `*.key`, credentials, and secrets
- [ ] No `ARG` instructions contain secrets (use BuildKit `--mount=type=secret` instead)
- [ ] No `RUN` commands embed tokens, passwords, or API keys
- [ ] Base images are pinned to a specific version tag or SHA256 digest
- [ ] `COPY` is used instead of `ADD` unless archive extraction is explicitly needed
- [ ] Multi-stage builds are used to exclude build tools and source from the final image
- [ ] Images are scanned with Trivy, Grype, or Snyk before deployment
- [ ] `HEALTHCHECK` directive is present for orchestration readiness

### Docker Compose

- [ ] No service uses `privileged: true`
- [ ] `cap_drop: [ALL]` is set with only necessary capabilities added back
- [ ] No volumes mount `/var/run/docker.sock`, `/`, `/etc`, `/proc`, `/sys`, or `/dev`
- [ ] Volumes are mounted read-only (`:ro`) where possible
- [ ] Internal services use `expose:` instead of `ports:`
- [ ] Published ports bind to `127.0.0.1` when behind a reverse proxy
- [ ] Resource limits (`mem_limit`, `cpus` or `deploy.resources.limits`) are set for all services
- [ ] Secrets use Docker secrets or external secret management, not plaintext `environment:` values
- [ ] Networks are segmented with `internal: true` for backend services
- [ ] `security_opt: [no-new-privileges:true]` is set on all services
- [ ] `read_only: true` is set with explicit `tmpfs` mounts for writable directories

### Kubernetes

- [ ] No pod runs as `runAsUser: 0` — `runAsNonRoot: true` is set at the pod level
- [ ] `readOnlyRootFilesystem: true` is set on all containers
- [ ] `allowPrivilegeEscalation: false` is set on all containers
- [ ] `capabilities.drop: [ALL]` is set; only required capabilities are added back
- [ ] `seccompProfile.type: RuntimeDefault` (or `Localhost`) is set
- [ ] `hostNetwork`, `hostPID`, and `hostIPC` are not set to `true`
- [ ] `privileged: true` is not used
- [ ] Resource `requests` and `limits` are set for both CPU and memory on all containers
- [ ] RBAC uses namespace-scoped `Role`/`RoleBinding` instead of `ClusterRole`/`ClusterRoleBinding` where possible
- [ ] No RBAC rules use wildcard (`*`) for verbs, resources, or apiGroups
- [ ] `cluster-admin` is not bound to application service accounts
- [ ] `NetworkPolicy` exists with default-deny ingress and egress per namespace
- [ ] Secrets use `external-secrets`, `sealed-secrets`, or a CSI secret store driver, not plaintext `Secret` resources
- [ ] Pod Security Admission (or Pod Security Standards) is enforced at the namespace level
- [ ] Service accounts have `automountServiceAccountToken: false` unless API access is needed

### Terraform

- [ ] No hardcoded credentials (`access_key`, `secret_key`, `password`, `token`) in `.tf` files
- [ ] Sensitive variables use `sensitive = true` flag
- [ ] Credentials are provided via environment variables, IAM roles, or external secret managers
- [ ] S3 buckets have `aws_s3_bucket_public_access_block` with all four blocks enabled
- [ ] S3 buckets have server-side encryption enabled (SSE-KMS preferred)
- [ ] S3 buckets have versioning enabled
- [ ] Security groups do not use `0.0.0.0/0` or `::/0` for ingress (especially on ports 22, 3389, 3306, 5432)
- [ ] RDS instances have `storage_encrypted = true` with a KMS key
- [ ] EBS volumes have `encrypted = true`
- [ ] CloudTrail is enabled with `is_multi_region_trail = true` and `enable_log_file_validation = true`
- [ ] VPC Flow Logs are enabled for all VPCs
- [ ] Terraform state is stored in an encrypted remote backend (S3 + DynamoDB with SSE-KMS)
- [ ] Terraform state bucket has versioning, logging, and access controls
- [ ] `user_data` scripts do not contain inline secrets (use IAM roles or Secrets Manager)
- [ ] `deletion_protection` is enabled on production databases and critical resources

### General IaC Practices

- [ ] All IaC files are scanned in CI/CD with tools like Checkov, tfsec, Trivy, or KICS
- [ ] Policy-as-code (OPA/Rego, Sentinel) enforces security guardrails before deployment
- [ ] IaC changes go through pull request review with security-focused reviewers
- [ ] Drift detection runs regularly to catch manual changes that bypass IaC
- [ ] Secrets scanning (Gitleaks, TruffleHog) runs on every commit to prevent credential leaks
- [ ] Infrastructure changes are applied through CI/CD pipelines, not from developer machines
