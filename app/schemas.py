"""HTTP contracts used on both sides of the local mock connection."""

from pydantic import BaseModel, Field, StrictInt
from common.agent import DEFAULT_AGENT_STEPS, MAX_AGENT_STEPS


class LoginIn(BaseModel):
    username: str
    password: str


class ChatIn(BaseModel):
    prompt: str
    max_output_tokens: StrictInt = Field(default=256, ge=1)
    agent_steps: StrictInt = Field(default=DEFAULT_AGENT_STEPS, ge=1, le=MAX_AGENT_STEPS)


class Usage(BaseModel):
    tokens_in: StrictInt = Field(ge=0)
    tokens_out: StrictInt = Field(ge=1)
    cost_usd: float = Field(ge=0, allow_inf_nan=False)


class Completion(BaseModel):
    text: str
    usage: Usage


class AgentStep(BaseModel):
    iteration: StrictInt = Field(ge=1)
    tool: str
    usage: Usage


class AgentCompletion(Completion):
    iterations: list[AgentStep]
    agent_steps: StrictInt = Field(ge=1, le=MAX_AGENT_STEPS)
    tokenizer: str
