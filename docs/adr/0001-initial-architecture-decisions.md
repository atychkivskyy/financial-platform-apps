# ADR-0001: Initial Architecture Decisions

## Status
Accepted

## Context

This project is a backend platform intended to demonstrate professional Java backend engineering practices, including service autonomy, event-driven design, and GitOps-based delivery.

The system is developed as a multi-service backend using Spring Boot and deployed using containerization and Kubernetes. Early architectural decisions were required to ensure scalability, maintainability, and production readiness.

## Decisions

### 1. Monorepo with Independent Services

The project uses a single Git repository containing multiple independent Spring Boot services.

Each service:
- Is a standalone Spring Boot application
- Has its own build configuration
- Is independently containerized and deployed
- Owns its data and configuration

There is no shared parent Maven module or shared runtime library.

**Rationale**
- Mirrors real-world microservice monorepos
- Avoids artificial coupling
- Simplifies CI/CD and GitOps workflows
- Allows services to evolve independently

---

### 2. Feature-Based Package Structure

Within each service, a feature-based (vertical slice) package structure is used instead of a type-based structure.

Example:
- user/
- api/
- application/
- domain/
- persistence/

**Rationale**
- Improves domain clarity
- Keeps related code together
- Reduces cross-package coupling
- Scales better as features grow
- Encourages domain-driven design

---

### 3. Domain-First Development Approach

Development follows a domain-first approach:

1. Domain model
2. Persistence layer
3. Application services
4. API layer
5. Security and infrastructure concerns

**Rationale**
- Avoids anemic domain models
- Keeps business rules explicit
- Improves testability
- Reduces framework-driven design

---

### 4. Database-per-Service Pattern

Each service owns its database schema and storage technology.

There is:
- No shared database
- No cross-service schema access
- No foreign keys across services

**Rationale**
- Enforces service ownership
- Enables independent scaling and deployment
- Avoids tight coupling at the data layer
- Supports eventual consistency

---

### 5. Event-Driven Communication

Asynchronous communication between services is handled via Apache Kafka.

Key principles:
- Events represent facts, not commands
- At-least-once delivery semantics
- Idempotent consumers
- Explicit retry and dead-letter topics
- Transactional outbox pattern where needed

**Rationale**
- Improves resilience
- Decouples services
- Enables eventual consistency
- Reflects modern backend architectures

---

### 6. Environment-Specific Configuration via Profiles

Spring profiles are used to separate configuration by environment.

- `application.yml` contains shared defaults
- `application-dev.yml` and `application-prod.yml` are environment-specific
- Real configuration files are not committed
- `.example` files document expected variables

**Rationale**
- Prevents leaking secrets
- Enables clean local development
- Aligns with container and Kubernetes deployment models

---

### 7. GitOps-Based Deployment Model

Application code and infrastructure definitions are stored in separate repositories.

- CI builds and tests applications
- CD is handled declaratively via GitOps
- Argo CD reconciles desired state
- No manual deployments to Kubernetes

**Rationale**
- Improves auditability
- Enables reproducible deployments
- Reduces human error
- Matches modern platform practices

## Consequences

- Slightly higher initial setup cost
- Stronger long-term maintainability
- Clear service boundaries
- Production-ready architecture from the start

These trade-offs are intentional and aligned with the project’s goals.
