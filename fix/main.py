from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Annotated, Optional

import urllib.request
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, PositiveInt

# --- structured logging у stdout (сигнал взаємодії для SIEM) ---
logger = logging.getLogger("user_api")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))


def log_event(event: str, **fields) -> None:
    logger.info(json.dumps({"event": event, **fields}, ensure_ascii=False))


app = FastAPI(
    title="user-api",
    version="1.0.0",
    description="Secure-by-Design шаблон із сигналами (OpenAPI/DTO/logging) та гейтами (CI/OPA/IaC).",
)

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = os.getenv("OPA_POLICY_PATH", "httpapi/allow")  # package httpapi; allow


# --- DTO / Pydantic (сигнали структури input/output) ---
class UserOut(BaseModel):
    id: PositiveInt
    name: str


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginOut(BaseModel):
    status: str
    token: Optional[str] = None


# --- кореляція запитів (сигнал трасування) ---
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}


# --- secrets: Vault CSI (файл) або env (fallback) ---
def read_secret(name: str) -> str:
    file_path = os.getenv(f"{name}_FILE")  # напр. APP_PASSWORD_FILE=/mnt/secrets-store/APP_PASSWORD
    if file_path:
        p = Path(file_path)
        if p.exists():
            return p.read_text(encoding="utf-8").strip()
    return os.getenv(name, "").strip()


# --- access context (сигнал для policy-as-code) ---
class AuthCtx(BaseModel):
    subject: str = "anonymous"
    scopes: list[str] = []


def parse_scopes(x_scopes: str | None) -> list[str]:
    if not x_scopes:
        return []
    return [s.strip() for s in x_scopes.split(",") if s.strip()]


def get_auth_ctx(
    authorization: Annotated[str | None, Header()] = None,
    x_scopes: Annotated[str | None, Header(alias="X-Scopes")] = None,
) -> AuthCtx:
    # Для лабораторної: bearer-токен = сигнал наявності AuthN, scopes передаємо окремим заголовком.
    if not authorization or not authorization.startswith("Bearer "):
        return AuthCtx(subject="anonymous", scopes=parse_scopes(x_scopes))
    token = authorization.removeprefix("Bearer ").strip()
    if len(token) < 10:
        return AuthCtx(subject="anonymous", scopes=parse_scopes(x_scopes))
    return AuthCtx(subject="user", scopes=parse_scopes(x_scopes))


def opa_allow(method: str, path: str, auth: AuthCtx) -> bool:
    url = f"{OPA_URL}/v1/data/{OPA_POLICY_PATH}"
    payload = {
        "input": {
            "method": method,
            "path": path,
            "subject": auth.subject,
            "scopes": auth.scopes,
        }
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            # OPA повертає {"result": true/false} або {"result":{"allow":...}} залежно від policy
            result = body.get("result", False)
            if isinstance(result, bool):
                return result
            if isinstance(result, dict) and "allow" in result:
                return bool(result["allow"])
            return False
    except Exception:
        return False


def authorize(request: Request, auth: AuthCtx = Depends(get_auth_ctx)) -> AuthCtx:
    rid = getattr(request.state, "request_id", None)
    allowed = opa_allow(request.method, request.url.path, auth)
    log_event(
        "authz.decision",
        request_id=rid,
        method=request.method,
        path=request.url.path,
        subject=auth.subject,
        scopes=auth.scopes,
        allowed=allowed,
    )
    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied by policy")
    return auth


@app.get("/user", response_model=UserOut, tags=["users"])
def get_user(id: PositiveInt, request: Request, _auth: AuthCtx = Depends(authorize)) -> UserOut:
    rid = getattr(request.state, "request_id", None)
    log_event("user.read", request_id=rid, user_id=int(id))
    return UserOut(id=id, name="Alice")


@app.post("/login", response_model=LoginOut, tags=["auth"])
def login(payload: LoginIn, request: Request) -> LoginOut:
    rid = getattr(request.state, "request_id", None)

    expected = read_secret("APP_PASSWORD")
    if not expected:
        log_event("auth.config.missing_secret", request_id=rid)
        raise HTTPException(status_code=500, detail="Auth секрет не налаштований")

    if payload.password == expected:
        log_event("auth.login.success", request_id=rid, username=payload.username)
        return LoginOut(status="ok", token="demo-token-please-replace")

    log_event("auth.login.fail", request_id=rid, username=payload.username)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
