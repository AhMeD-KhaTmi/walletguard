"""HTTP contracts used on both sides of the local mock connection."""

from pydantic import BaseModel, Field, StrictInt


class LoginIn(BaseModel):
    username: str
    password: str


class ChatIn(BaseModel):
    prompt: str
    max_output_tokens: StrictInt = Field(default=256, ge=1)


class Usage(BaseModel):
    tokens_in: StrictInt = Field(ge=1)
    tokens_out: StrictInt = Field(ge=1, le=32_000)
    cost_usd: float = Field(ge=0, allow_inf_nan=False)


class Completion(BaseModel):
    text: str
    usage: Usage
