"""Exact synthetic demo prices; integer micro-USD, never live provider pricing."""
from common.agent import reserve_tokens, MOCK_OUTPUT_CAP
INPUT_MICROUSD=3
OUTPUT_MICROUSD=15
IN_PER_1K=INPUT_MICROUSD/1000
OUT_PER_1K=OUTPUT_MICROUSD/1000


def cost_microusd(tokens_in:int,tokens_out:int)->int:
    return tokens_in*INPUT_MICROUSD+tokens_out*OUTPUT_MICROUSD


def reserve_microusd(prompt:str,output:int,steps:int)->int:
    output=min(output,MOCK_OUTPUT_CAP)
    total=reserve_tokens(prompt,output,steps)
    return cost_microusd(total-output*steps,output*steps)
