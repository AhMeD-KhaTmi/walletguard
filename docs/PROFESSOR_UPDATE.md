# Professor feedback implementation

The user supplied [this comparison PDF](masterplan_vs_professor_diff.pdf) as the
professor's requested changes. Master plan v1.3 and both member plans adopt its
reported conditions. Optional interface suggestions remain optional.

| Requirement | Current implementation or owner |
|---|---|
| Realistic simulated agent behavior | B implemented a 1–8-step catalogue loop, default 3, with growing context and one backend HTTP connection per step |
| Exact mock tokens | Shared synthetic whitespace tokenizer counts words exactly; per-step and total usage are validated |
| Simulated latency | Configurable throughput, base delay, deterministic jitter, cap and seed; saved in manifests |
| Ubuntu LTS, kernel >=5.15, BTF | Check script and [environment evidence](evidence/professor_environment.json) |
| XDP fallback | A's plan specifies native then generic/skb, or explicit tc/nftables/WAF fallback with mode and evidence |
| Syscall scope | A's initial scope is app-attributed connect and execve; real sensor implementation is pending |
| FPR, p50/p95 and C0-relative overhead | Metrics collector reports finalized WAF p50/p95; current benchmark includes matched C0 runs and client percentile deltas |
| Optional OpenAI/Ollama demo | Optional extension; all measured campaigns use the local synthetic mock |

The tokenizer is explicitly a synthetic model tokenizer. No equivalence to a
provider's tokenizer is claimed. One token is a nonempty Unicode-whitespace-delimited
word. Empty input has zero tokens. Agent observations and role markers are counted
when repeated context is sent to the mock. Per-step output tokens are counted from
generated text. A request may return a final text with fewer tokens than its
aggregate usage because usage includes earlier iterations.

`agent_steps` is a strict JSON integer. Whole-task reservations cover all steps
before the first backend call. Usage from confirmed steps survives a later failure.
Known connection failures permit unused-reservation refunds, and ambiguous timeouts
keep the reservation. The mock's own call/token counters provide independent evidence.

Feature version 3 adds step count and task budget. The previous datasets, model,
held-out scores and 54-run benchmark describe version 2. Preserve those artifacts
and use fresh version-3 runs for current model training and measurement.

New raw C1 captures and split files are under `ml/data/professor-agent3/` locally.
Run `scripts/check_environment.py` before kernel integration. Run the app using
the existing demo launcher, with a compatible model for C3. The sensor and C4
remain the next joint integration point.

## Completed checks and measured results

Application/contract tests passed **75 cases**, evaluation tests **109**, and
real HTTP development checks **12**. Six namespace smoke runs passed. Browser
testing in C3 confirmed three iterations with input counts 2/19/36, eight output
tokens per step, aggregate usage 57 input + 24 output, and simulated cost $0.000531.
See [current metadata](evidence/professor_update.json) and
[HTTP checks](evidence/professor_http_checks.json).

The [81-run C0/C2/C3 benchmark](PROFESSOR_BENCHMARK_RESULTS.md) is complete at
clean measured revision `aa51185`. Every run has matching independent API/mock
token counts. Both plans and the simple team checklist track this as completed
measurement work. The old 54-run report remains historical.

Fresh feature-version-3 model evaluation: precision **66.67%**, recall **0.0397%**,
benign detector FPR **1.047%**. The very low recall remains a limitation. Combined
WAF enforcement FPR in the benchmark was **2.350% C2** and **2.271% C3**, with one
benign budget auto-ban each; the original ≤1% and zero-benign-ban targets are
unmet. B can collect independent calibration data and improve budgets/model
performance while A develops the kernel layer. Keep the existing held-out set
and benchmark frozen. The measured application work does not establish final
security acceptance or C4 readiness.
