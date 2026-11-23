# 05 — Reading the graph

A BloodHound collection is only worth what you extract from it. This chapter answers one question for
each of our accounts: **is there any object in this directory we can write to?** The answer is no, and
the way it is no is worth documenting, because it redirects the whole engagement back to credential
attack.

---

## 5.1 Who actually is Domain Admin

```
DOMAIN ADMINS@OSCP.EXAM
   -> TOM_ADMIN@OSCP.EXAM
   -> ADMINISTRATOR@OSCP.EXAM

ENTERPRISE ADMINS@OSCP.EXAM
   -> ADMINISTRATOR@OSCP.EXAM

GROUP POLICY CREATOR OWNERS@OSCP.EXAM
   -> ADMINISTRATOR@OSCP.EXAM
```

`TOM_ADMIN` is the interesting name: a human-looking administrative account alongside the built-in
`Administrator`. Those are the two identities that end this engagement. Everything else is a means of
becoming one of them.

---

## 5.2 The question that decides the path

For each account we hold, scan **every object in the directory** for an ACE whose principal is that
account:

```
OUTBOUND EDGES: objects our accounts can CONTROL
  NONE. Our accounts hold no delegated rights over any object in this dataset.
```

Not "few". None. `celia.almeda`, `web_svc` and `eric.wallows` hold no `GenericAll`, `GenericWrite`,
`WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddKeyCredentialLink`, `DCSync` or `AddMember`
anywhere.

Their group memberships confirm it independently — none of them is in the delegated business groups:

| Group | Members | Ours? |
|---|---|---|
| `ADMIN` | Donna Johnson, Luke Martin, Chelsea Byrne, Sandra Craig, Leonard Morris | no |
| `IT` | Oliver Gray, Kenneth Coles, Carol Webb | no |
| `FINANCE` | Shane Mitchell, Jamie Thomas, Linda Patel, Emily Bishop, Lawrence Kay | no |
| `HR` | Joan North, Jane Booth, Frank Farrell | no |
| `MARKETING` | Janice Turner, Thomas Robinson, Aimee Hunt, Georgina Begum | no |
| `IIS_IUSRS` | `OSCP.EXAM-S-1-5-17` | no |

That is a clean negative result, and it is the most important sentence in this chapter: **there is no
ACL path to Domain Admin from the accounts currently held.** ACL work, `GenericAll` abuse, `WriteDacl`
chains — all of it is off the table until a new account is acquired.

---

## 5.3 Two other paths, both closed

**LAPS is not deployed.** `haslaps` is `false` on all three computers, so local administrator passwords
are not randomised and not readable. There is no `ReadLAPSPassword` shortcut because there is no LAPS.

**There are no sessions to steal.** Session collection returned `collected=true` with **zero results**
on all three computers:

```
MS02.OSCP.EXAM   sessions[collected=True n=0]
MS01.OSCP.EXAM   sessions[collected=True n=0]
DC01.OSCP.EXAM   sessions[collected=True n=0]
```

No Domain Admin is logged on to a member server, so there is nothing to relay or impersonate on MS02
despite its SMB signing being off. This may partly be an artefact of the NTLM fallback in chapter 04 —
a Kerberos-backed collection could show sessions this run missed — so treat it as "not observed" rather
than "proven absent".

DC01's local administrators are the default trio (`Administrator`, `Enterprise Admins`,
`Domain Admins`) — correct for a domain controller, and offering nothing.

---

## 5.4 Reading the export correctly

One trap cost time here and is worth recording.

In a `bloodhound-python` legacy export, each object's `Aces` array contains ACEs **on that object**. For
an inbound ACE, `PrincipalSID` is the **grantor** — the principal who holds the right — not the object's
owner. Filtering `Aces` on a user therefore answers "*who can control this user*", not "*what can this
user control*".

Read the wrong way, every user in the domain appears to hold `GenericAll` over `Domain Admins`, which is
nonsense on its face: the same four rights appear identically for unrelated accounts, and the
`PrincipalSID` resolves to `-512` (`Domain Admins`) rather than to the user.

The correct question — *what can this account control* — requires scanning **all** objects and matching
`PrincipalSID` against our accounts' SIDs. That is what section 5.2 does, and it comes back empty.

---

## 5.5 What the graph does tell us

| Fact | Consequence |
|---|---|
| DA = `TOM_ADMIN`, `Administrator` | these are the two end states |
| No outbound ACEs for our accounts | ACL abuse unavailable |
| Not in `ADMIN`/`IT`/`FINANCE`/… | no group-derived privilege |
| No LAPS | no local-admin password shortcut |
| No sessions observed | relay/impersonation has no target |
| `sql_svc` password last set 2022-12-05 | a stale, roastable service account |
| `web_svc` password last set 2022-11-10 | already owned |

Every row points the same way. With no writable object and no privileged session, the only remaining
lever is **a credential we do not yet have** — and the graph names the best candidate: `sql_svc`.

That converges exactly with chapter 03 (the SQL service account is the context `xp_cmdshell` would run
in) and chapter 04 (it is Kerberoastable). Three independent lines of reasoning, one target.

---

## 5.6 Position after this chapter

| Path | Status |
|---|---|
| ACL abuse | **closed** — zero outbound rights |
| Group-derived privilege | **closed** — not in any delegated group |
| LAPS read | **closed** — not deployed |
| Session theft / relay | **no target observed** |
| Kerberoast `sql_svc` | **open** — blocked only on DNS + clock |
| DC01 `Users` share | **unexamined** |
| SQL `xp_dirtree` capture | **untested** |

The engagement is now purely a credential problem, and there are two candidate sources: a roastable
service account and an unexamined share on the DC.
