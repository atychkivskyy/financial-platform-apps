# Finance Platform – Backend Services

## Overview

This repository contains the **application services** of a cloud-native, event-driven **financial transactions platform** built to demonstrate **professional Java backend engineering practices**.

The system is designed using **Spring Boot 4**, **Java 21**, and **modern DevOps/GitOps principles**, with a strong focus on:

- Clean architecture and service boundaries
- Correctness and data consistency
- Event-driven communication
- Observability and production readiness
- Declarative delivery via GitOps

This project is intended as a **showcase backend system**, not a toy example.

---

## High-Level Architecture

The platform follows a **distributed, stateless microservices architecture** with:

- REST APIs for synchronous interactions
- Apache Kafka for asynchronous, event-driven communication
- Database-per-service pattern
- GitOps-based deployment model

### Services

| Service | Responsibility | Storage |
|------|---------------|--------|
| `api-gateway` | Request routing, auth propagation | — |
| `auth-service` | Authentication, JWT issuance | PostgreSQL |
| `account-service` | Account management, balances | PostgreSQL |
| `transaction-service` | Transaction processing, event emission | PostgreSQL |
| `audit-service` | Immutable audit/event storage | MongoDB |

Each service is:
- Independently deployable
- Stateless
- Owned by a single bounded context
- Responsible for its own data

---

## Architectural Principles

### 1. Stateless Services
All services are stateless. Session state is never stored in memory, enabling horizontal scalability and fault tolerance.

---

### 2. Database per Service
Each service owns its data store and schema.  
There is **no shared database access** between services.

This enforces:
- Clear ownership
- Loose coupling
- Independent evolution

---

### 3. Event-Driven Communication
Cross-service communication for business events is handled via **Apache Kafka**.

Key principles:
- Events represent facts, not commands
- At-least-once delivery
- Idempotent consumers
- Explicit retry and dead-letter topics
- Transactional outbox pattern for consistency

---

### 4. Consistency Model
The system embraces **eventual consistency** across services.

Strong consistency is guaranteed **within a single service boundary** using local database transactions.

---

### 5. Security Model
- Stateless authentication using JWT
- Centralized authentication
- Role-based authorization
- Password hashing using modern algorithms
- No security logic in controllers

---

### 6. Observability First
Each service exposes:
- Structured logs
- Prometheus-compatible metrics
- Health and readiness endpoints

System health is monitored via **Prometheus** and visualized in **Grafana** dashboards.

---

### 7. GitOps Delivery Model
This repository contains **application code only**.

- CI builds and tests the applications
- Container images are published by CI
- Deployment is handled declaratively via a separate **infrastructure repository**
- Argo CD continuously reconciles desired state

There are **no imperative deployments** to Kubernetes.

---

## Technology Stack

### Backend
- Java 21
- Spring Boot 4
- Spring Framework 7
- Spring Security 7

### Data
- PostgreSQL 18
- MongoDB

### Messaging
- Apache Kafka 4

### Observability
- Micrometer
- Prometheus
- Grafana

### Delivery
- Docker
- Kubernetes
- GitHub Actions (CI)
- Argo CD (GitOps CD)

---

## Repository Structure (Planned)

```text
/services
  /api-gateway
  /auth-service
  /account-service
  /transaction-service
  /audit-service
