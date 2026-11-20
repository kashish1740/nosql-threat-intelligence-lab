"""Chapter 15: a multi-tenant case service.

Tenant = organisation. Every case carries tenant_id and every query is scoped by it, so a case of
another tenant answers 404. An org admin manages all of the tenant's cases; a member only their own
(403). Each user may make RATE_LIMIT requests per minute, counted in MongoDB with $inc + upsert and
expired by a TTL index; above that the API answers 429 with Retry-After.
"""
import datetime as dt
import os
import time
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.platform import audit, clean, pdb, require, signed_in, utcnow

RATE_LIMIT = int(os.getenv("CASES_RATE_LIMIT", "30"))
router = APIRouter(prefix="/api")


class RateLimited(Exception):
    def __init__(self, retry_after):
        self.retry_after = retry_after


def rate_limited_handler(request, exc: RateLimited):
    return JSONResponse({"detail": f"Too many requests: limit is {RATE_LIMIT} per minute. Try again in {exc.retry_after} s.",
                         "retry_after": exc.retry_after}, status_code=429, headers={"Retry-After": str(exc.retry_after)})


def member(user=Depends(signed_in)):
    """The signed-in user, who must belong to an organisation; also applies the rate limit."""
    if not user.get("org"):
        raise HTTPException(403, "Your account does not belong to an organisation. Ask an administrator to add you.")
    now = time.time()
    window = int(now // 60)
    key = f"{user['_id']}:{window}"
    d = pdb()
    try:
        doc = d.rate_limits.find_one_and_update({"_id": key}, {"$inc": {"count": 1}, "$setOnInsert": {
            "user": user["_id"], "org": user["org"], "expires_at": utcnow() + dt.timedelta(minutes=2)}},
            upsert=True, return_document=ReturnDocument.AFTER)
    except DuplicateKeyError:
        doc = d.rate_limits.find_one_and_update({"_id": key}, {"$inc": {"count": 1}}, return_document=ReturnDocument.AFTER)
    if doc["count"] > RATE_LIMIT:
        d.rate_refusals.update_one({"_id": f"{user['org']}:{utcnow():%Y-%m-%d}"},
                                   {"$inc": {"count": 1}, "$setOnInsert": {"org": user["org"], "day": f"{utcnow():%Y-%m-%d}"}}, upsert=True)
        raise RateLimited(max(1, 60 - int(now % 60)))
    return user


def scoped(user, case_id=None, write=False):
    query = {"tenant_id": user["org"]}
    if case_id:
        query["_id"] = case_id
    return query


def load(user, case_id):
    doc = pdb().cases.find_one(scoped(user, case_id))
    if not doc:
        raise HTTPException(404, "Case not found")
    if user["org_role"] != "admin" and doc["owner"] != user["_id"]:
        raise HTTPException(403, "Only the case owner or an organisation admin can see or change this case.")
    return doc


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    threat_ref: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=2000)


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    priority: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["open", "investigating", "closed"] | None = None
    assignee: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=2000)


@router.get("/labs/jwks")
def jwks():
    return {"keys": [], "note": "Demo sign-in uses an HMAC-signed session issued by this server, so there is no public JWKS. "
                                "Lab 15's standalone task API (labs/ch15/api.py) shows the verified-JWT variant."}


@router.get("/cases/me")
def cases_me(user=Depends(member)):
    d = pdb()
    org = d.organisations.find_one({"_id": user["org"]}) or {}
    mine = d.cases.count_documents({"tenant_id": user["org"], "owner": user["_id"]})
    total = d.cases.count_documents({"tenant_id": user["org"]}) if user["org_role"] == "admin" else None
    return clean({"org": user["org"], "org_name": org.get("name", user["org"]), "org_role": user["org_role"], "mine": mine,
                  "org_total": total, "open": d.cases.count_documents({"tenant_id": user["org"], "status": "open"}),
                  "rate_limit_per_minute": RATE_LIMIT})


@router.get("/cases")
def list_cases(status: str | None = Query(None, max_length=20), priority: str | None = Query(None, max_length=20), user=Depends(member)):
    query = scoped(user)
    if user["org_role"] != "admin":
        query["owner"] = user["_id"]
    if status:
        query["status"] = status
    if priority:
        query["priority"] = priority
    return clean(list(pdb().cases.find(query).sort("created_at", -1).limit(200)))


@router.post("/cases", status_code=201)
def create_case(body: CaseIn, user=Depends(member)):
    doc = {"_id": "CASE-" + uuid.uuid4().hex[:8].upper(), "tenant_id": user["org"], "owner": user["_id"], "assignee": user["_id"],
           "status": "open", "created_at": utcnow(), "updated_at": utcnow(), **body.model_dump()}
    pdb().cases.insert_one(doc)
    audit("case.create", user["_id"], case=doc["_id"], org=user["org"], threat_ref=body.threat_ref or "")
    return clean(doc)


@router.get("/cases/org/members")
def org_members(user=Depends(member)):
    if user["org_role"] != "admin":
        raise HTTPException(403, "Only an organisation admin can list members.")
    rows = list(pdb().users.find({"org": user["org"]}, {"name": 1, "org_role": 1, "role": 1}))
    for r in rows:
        r["cases"] = pdb().cases.count_documents({"tenant_id": user["org"], "owner": r["_id"]})
    return clean(rows)


@router.get("/cases/{case_id}")
def get_case(case_id: str, user=Depends(member)):
    return clean(load(user, case_id))


@router.patch("/cases/{case_id}")
def update_case(case_id: str, body: CasePatch, user=Depends(member)):
    doc = load(user, case_id)
    changes = {k: v for k, v in body.model_dump().items() if k in body.model_fields_set and v is not None}
    if "assignee" in changes:
        if user["org_role"] != "admin":
            raise HTTPException(403, "Only an organisation admin can reassign cases.")
        if not pdb().users.find_one({"_id": changes["assignee"], "org": user["org"]}):
            raise HTTPException(422, "The assignee must belong to your organisation.")
    changes["updated_at"] = utcnow()
    updated = pdb().cases.find_one_and_update({"_id": doc["_id"], "tenant_id": user["org"]}, {"$set": changes}, return_document=ReturnDocument.AFTER)
    audit("case.update", user["_id"], case=case_id, fields=",".join(sorted(changes)))
    return clean(updated)


@router.delete("/cases/{case_id}", status_code=204)
def delete_case(case_id: str, user=Depends(member)):
    try:
        load(user, case_id)
        if user["org_role"] != "admin":
            raise HTTPException(403, "Only an organisation admin can delete cases.")
    except HTTPException as exc:
        audit("case.delete", user["_id"], outcome=f"denied_{exc.status_code}", case=case_id)
        raise
    pdb().cases.delete_one({"_id": case_id, "tenant_id": user["org"]})
    audit("case.delete", user["_id"], case=case_id)


@router.get("/moderation/organisations")
def organisations(user=Depends(require("moderator", "admin"))):
    d = pdb()
    rows = []
    for org in d.organisations.find():
        by_status = {r["_id"]: r["n"] for r in d.cases.aggregate([{"$match": {"tenant_id": org["_id"]}}, {"$group": {"_id": "$status", "n": {"$sum": 1}}}])}
        rows.append({"org": org["_id"], "name": org["name"], "members": d.users.count_documents({"org": org["_id"]}),
                     "cases": sum(by_status.values()), "by_status": by_status,
                     "rate_limit_refusals": sum(r["count"] for r in d.rate_refusals.find({"org": org["_id"]}))})
    return clean(rows)
