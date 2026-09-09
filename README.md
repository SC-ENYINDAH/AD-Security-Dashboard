# 🛡️ Active Directory Security and Audit Dashboard

<img width="1782" height="426" alt="Screenshot 2026-09-09 184214" src="https://github.com/user-attachments/assets/69836985-6040-47f2-8603-4308540f00d8" />

<div align="center">

### Enterprise Active Directory Security Monitoring, Auditing and Administration Framework

_A modular PowerShell platform designed for Active Directory auditing, threat detection, administrative operations, and security posture assessments through LDAP and PowerShell Remoting._

</div>

---

# 📖 Overview

Active Directory remains the backbone of identity and access management in most enterprise environments. Misconfigurations, stale accounts, excessive privileges, weak password practices, and poor visibility often become the root cause of security incidents.

The **Active Directory Security and Audit Dashboard** is an enterprise-focused PowerShell framework designed to simplify Active Directory security assessments, operational monitoring, threat detection, and administrative management.

The platform was built to address a common challenge faced by security teams and system administrators to gain deeper visibility into Active Directory environments while providing a centralized platform for security auditing and administration.


The framework provides:

- LDAP-Based Active Directory Enumeration
- PowerShell Remoting Support
- Security Auditing & Reporting
- Active Directory Administration
- Threat Hunting Capabilities
- Session Management
- Role-Based Access Control (RBAC)
- Dynamic Backend Switching
- Modular PowerShell Architecture
- Extensible Plugin-Based Design

---

# 🎯 Project Goals

The primary objectives of this project are:

Strengthen Active Directory visibility
Assist Blue Team operations
Detect misconfigurations
Support security auditing
Improve administrative efficiency
Provide reusable PowerShell modules
Encourage community contributions

# 🚀 Key Features

## 🔍 Active Directory Security Auditing

Perform deep security assessments through either:

### LDAP Backend

Directly queries Active Directory using LDAP communication.

### PSRemote Backend

Performs remote execution against Domain Controllers and management servers using PowerShell Remoting.

---

## 🛡 Security Audit Modules

Current audit modules include:

| Capability                      | Description                                    |
| ------------------------------- | ---------------------------------------------- |
| Privileged Group Audit          | Detects privileged group memberships           |
| Stale User Discovery            | Finds inactive accounts                        |
| Stale Computer Discovery        | Finds inactive devices                         |
| Non-Expiring Password Detection | Identifies risky password configurations       |
| Locked-Out Account Discovery    | Detects account lockouts                       |
| Kerberoasting Exposure          | Finds SPN-enabled accounts                     |
| AS-REP Roast Detection          | Detects vulnerable accounts                    |
| Unconstrained Delegation Audit  | Detects delegation risks                       |
| AdminSDHolder Analysis          | Audits protected accounts                      |
| Domain Trust Enumeration        | Maps trust relationships                       |
| Password Policy Analysis        | Reviews password settings                      |
| Brute Force Detection           | Identifies suspicious authentication failures  |
| Malicious Process Detection     | Detects suspicious parent-child process chains |


---

# 🔧 Administrative Functions

The platform does not stop at auditing.

Authorized users can perform Active Directory administrative operations directly from the dashboard.

### User Management

- Enable User Accounts
- Disable User Accounts
- Reset User Passwords
- Unlock Locked-Out Accounts
- Delete User Accounts

### Group Management

- Add User To Group
- Remove User From Group

### Computer Management

- Reset Computer Accounts
- Move Computer Objects Between OUs

---

# 🏗 System Architecture

┌────────────────────────────────────────────┐
│                USER LOGIN                  │
└────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────┐
│          SESSION MANAGEMENT LAYER          │
└────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────┐
│        ROLE-BASED ACCESS CONTROL           │
└────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────┐
│         CONNECTION SELECTION LAYER         │
└────────────────────────────────────────────┘
             │                    │
             ▼                    ▼

      LDAP BACKEND         PSREMOTE BACKEND

             └────────┬───────────┘
                      │
                      ▼
┌────────────────────────────────────────────┐
│          DYNAMIC MENU ENGINE               │
└────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────┐
│       COMMAND EXECUTION FRAMEWORK          │
└────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────┐
│    AUDIT • ADMINISTRATION • REPORTING      │
└────────────────────────────────────────────┘


---

# 🔒 Security Features

## Role-Based Access Control (RBAC)

The framework utilizes fine-grained role-based access control to ensure users only access permitted functionality.

### Supported Roles

ADMIN

SYSTEM ADMIN

SOC ANALYST

DEVELOPER

EMPLOYEE


### Enforcement

RBAC is enforced at execution time, not merely through menu visibility.

Unauthorized command execution attempts are denied automatically.

---

## Session Management

### Features

- Secure User Authentication
- Activity Tracking
- Session Monitoring
- User Logout Support
- Session State Management
- Dynamic Role Validation

### Idle Timeout Protection

The platform automatically terminates inactive sessions.

```text
Session Timeout: 300 Seconds
```

Upon timeout:

- User session is terminated
- Backend connection is released
- User is redirected to login
- Activity is recorded in logs

---

# 🔄 Dynamic Backend Switching

One of the core capabilities of the platform is dynamic backend abstraction.

The same command automatically routes to either the LDAP or PSRemote implementation.

Example:

```text
Get-StaleUsers-ldap
```

or

```text
Get-StaleUsers-ps
```

depending on the active backend selected by the user.

### Benefits

- Reduced code duplication
- Easier maintenance
- Improved scalability
- Future backend expansion

---

# 📊 Logging & Alerting

The platform records operational events and security findings.

### Logged Activities

- Authentication Events
- Administrative Actions
- Security Findings
- Threat Detection Events
- Connection Changes
- Session Timeouts
- Permission Violations

### Alerting

Supports severity-based alerting:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Future integrations include:

- Email Notifications
- SIEM Alert Forwarding
- Microsoft Sentinel
- Elastic Stack


# 📂 Project Structure

AD-Security-Dashboard/

│
├── Dashboard.ps1
│
├── Modules/
│   ├── ldap_connect.psm1
│   ├── ps_remote_connect.psm1
│   └── connection_setup.psm1
│
├── Logs/
│
├── Reports/
|
├── README.md
│
├── LICENSE
│
└── .gitignore


# ⚙️ Installation

## Clone the Repository

```powershell
git clone https://github.com/SC-ENYINDAH/AD-Security-Dashboard.git
```

## Navigate to Project

```powershell
cd AD-Security-Dashboard
```

## Run the Dashboard

```powershell
.\Dashboard.ps1
```

---

# 🧪 Supported Technologies

## Core Technologies

- PowerShell 5.1+
- LDAP
- Active Directory
- ADSI
- DirectorySearcher
- DirectoryEntry
- WinRM
- PowerShell Remoting

---

# 🎯 Use Cases

## Security Auditors

- Identify Active Directory misconfigurations
- Review privileges
- Assess password policies

---

## SOC Analysts

- Investigate authentication events
- Detect brute-force activity
- Hunt suspicious behaviors

---

## Active Directory Administrators

- Reset passwords
- Unlock accounts
- Manage group memberships
- Perform administrative tasks

---

## Blue Team Operations

- Run continuous security reviews
- Detect attack paths
- Improve Active Directory hygiene

---

# 📈 Project Roadmap

## Version 2.0

Upcoming Features:

### Security Enhancements

- Advanced Threat Detection
- MITRE ATT&CK Mapping
- Security Score Cards
- Risk Prioritization Engine

### Reporting

- PDF Reporting
- Dashboard Visualization
- Scheduled Reports
- Historical Trend Analysis

### Integrations

- Microsoft Sentinel
- Elastic Stack
- Splunk
- Microsoft Defender
- M365 Security

### Enterprise Features

- Multi-Domain Support
- Multi-Forest Auditing
- Centralized Management Console
- Web-Based Dashboard

---

# 🤝 Contributing

Contributions are highly encouraged

# 🎖 Why This Project Matters

Active Directory remains one of the most targeted technologies in enterprise environments.

Many security incidents begin with:

Weak permissions
Stale accounts
Misconfigured delegation
Excessive privileges
Poor visibility

This project aims to provide security professionals with an extensible, open-source framework capable of improving both visibility and operational efficiency.

# 👨‍💻 Author
**Sampson Chinecherem Enyindah**

Cybersecurity Practitioner | Security Operations | Active Directory Security | Blue Team Engineering

Focused on building practical security solutions that bridge administration, automation, and threat detection.
