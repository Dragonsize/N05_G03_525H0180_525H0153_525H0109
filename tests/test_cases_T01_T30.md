# Security Test Plan & Results (T01 – T30)

**Project:** Design, Implement, and Audit Secure Access Control (University Records System)  
**Course:** Information Security – Ton Duc Thang University (TDTU)  
**Instructor:** Huynh Ngoc Tu, Ph.D.  
**Primary Responsibility:** Student C – Huynh Thien An (525H0109)  
**Group Members:**
- Tran Thanh Phat – 525H0180 (Student A: Threat Modeling & Access-Control Design)
- Nguyen Minh Khoi – 525H0153 (Student B: Authentication, Authorization & Web Implementation)
- Huynh Thien An – 525H0109 (Student C: Database Security, Testing & Audit Logging)

---

## 1. Test Suite Summary

| Category | Required by Spec | Implemented Test IDs | Total Tests | Pass Rate |
| :--- | :---: | :--- | :---: | :---: |
| **Authentication & Session Security** | >= 5 | `T01`, `T02`, `T03`, `T04`, `T05`, `T26`, `T28` | 7 | 100% (7/7) |
| **Server-Side & Record-Level Authorization (RBAC)** | >= 10 | `T06`, `T07`, `T08`, `T09`, `T10`, `T11`, `T12`, `T13`, `T15`, `T16`, `T17`, `T24`, `T27`, `T29` | 14 | 100% (14/14) |
| **Injection, Input Validation & Error Handling** | >= 3 | `T18`, `T19`, `T25`, `T30` | 4 | 100% (4/4) |
| **Audit Logging & Append-Only DB Integrity** | >= 2 | `T14`, `T20`, `T21`, `T22`, `T23` | 5 | 100% (5/5) |
| **TOTAL** | **>= 25** | **`T01` – `T30` (20 Mandatory + 10 Extended)** | **30** | **100% (30/30)** |

---

## 2. How to Run the Automated Test Suite

From the project root directory, run:

```bash
python tests/test_security.py