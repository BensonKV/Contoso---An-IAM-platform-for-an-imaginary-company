# Contoso IAM Platform

A hands-on Identity and Access Management (IAM) platform built around a fictional organization, **Contoso**.

This project demonstrates practical IAM concepts including authentication, authorization, role-based access control (RBAC), group-based access control, identity lifecycle management, session management, and integration between a Flask application and Keycloak using OpenID Connect.

---

## 📌 Project Overview

Identity and Access Management is a fundamental component of modern cybersecurity.

Organizations need to ensure that:

- Users are properly authenticated.
- Users can access only the resources they are authorized to use.
- Access can be granted based on roles and groups.
- Employee access changes when their responsibilities change.
- Access is revoked when an employee leaves the organization.
- Authentication sessions are handled securely.
- Applications can delegate authentication to a centralized Identity Provider.

To understand these concepts practically, this project simulates the IAM environment of a fictional company called **Contoso**.

The project uses **Keycloak as the Identity Provider (IdP)** and a **Flask-based Finance Portal** as a protected application.

---

# 🎯 Objectives

The main objectives of this project are to gain practical experience with:

- Identity and Access Management
- Authentication
- Authorization
- Role-Based Access Control (RBAC)
- Group-Based Access Control
- Identity Providers (IdP)
- OpenID Connect (OIDC)
- OAuth 2.0 concepts
- User and group management
- Session management
- Joiner-Mover-Leaver (JML) lifecycle
- Access provisioning and deprovisioning
- Application integration with Keycloak
- Secure handling of application secrets
- Docker-based IAM deployment

---

# 🏢 Scenario

The project simulates an organization called **Contoso**.

Contoso has multiple departments, including:

- Engineering
- Finance

Different employees require access to different applications and resources.

For example:

| Department | Example Access |
|------------|----------------|
| Engineering | Engineering resources |
| Finance | Finance Portal |
| Other Users | No access to restricted Finance resources |

Instead of implementing authentication independently inside every application, Contoso uses **Keycloak as a centralized Identity Provider**.

The Finance Portal relies on Keycloak for authentication and uses the authenticated user's identity and authorization information to determine whether access should be granted.

---

# 🏗️ Architecture

The high-level architecture of the project is:

```text
                        ┌──────────────────────┐
                        │        User          │
                        └──────────┬───────────┘
                                   │
                                   │ Login
                                   ▼
                        ┌──────────────────────┐
                        │   Finance Portal     │
                        │    Flask App         │
                        └──────────┬───────────┘
                                   │
                                   │ OpenID Connect
                                   ▼
                        ┌──────────────────────┐
                        │      Keycloak        │
                        │   Identity Provider  │
                        └──────────┬───────────┘
                                   │
                       ┌───────────┴───────────┐
                       │                       │
                       ▼                       ▼
                ┌──────────────┐        ┌──────────────┐
                │ Engineering  │        │   Finance    │
                │    Group     │        │    Group     │
                └──────────────┘        └──────────────┘

Refer screenshots/ for further understanding