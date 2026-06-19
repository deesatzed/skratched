# CAM Model Bake-Off: finESS

Date: 2026-06-17

## Purpose

Compare the current CAM mining model against three candidate OpenRouter models on one fixed repository: `/Volumes/WS4TB/WS4TBr/finESS`.

The goal is to see whether any candidate mines better than the current baseline for CAM-style repository methodology extraction.

## Controls

- Repo: `/Volumes/WS4TB/WS4TBr/finESS`
- Command shape: `cam mine ... --force-rescan --no-tasks --depth 1 --max-repos 1 --max-minutes 20`
- Tasks disabled to remove task-store noise.
- Each run used an isolated temp config and temp CAM DB under `/private/tmp/skratched-cam-bakeoff`.
- SDK fallback models were disabled in each temp config.
- All CAM agent slots were pinned to the same model for that run.
- OpenRouter key came from `/Volumes/WS4TB/camcxBU64/CAM_CAM/.env`; key values were not printed.

## Config And Logs

- Baseline config: `/private/tmp/skratched-cam-bakeoff/configs/baseline_deepseek_v4_flash.toml`
- Kimi config: `/private/tmp/skratched-cam-bakeoff/configs/moonshot_kimi_k27_code.toml`
- GLM config: `/private/tmp/skratched-cam-bakeoff/configs/zai_glm_52.toml`
- Nemotron config: `/private/tmp/skratched-cam-bakeoff/configs/nvidia_nemotron_3_ultra_550b_a55b.toml`
- Logs: `/private/tmp/skratched-cam-bakeoff/logs/`

The normal CAM production config remains `/Volumes/WS4TB/camcxBU64/CAM_CAM/claw.toml`.

## Results

| Model | OpenRouter availability | Findings | TS/Python split | Tokens | Time | JSON repairs | Timeouts/recovery | Capability fallbacks | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `deepseek/deepseek-v4-flash` | OK | 16 | 8 / 8 | 147,277 | 188.0s | 1 | 0 / 0 | 3 | Fastest and already integrated, but lower yield and some reasoning-field/capability JSON issues. |
| `moonshotai/kimi-k2.7-code` | OK | 23 | 12 / 11 | 266,025 | 824.4s | 1 | 1 / 1 | 4 | Highest yield, but very slow and needed content-reduction recovery. |
| `z-ai/glm-5.2` | OK | 21 | 12 / 9 | 142,673 | 331.6s | 2 | 0 / 0 | 3 | Best balance in this run: higher yield than baseline with similar token use, but slower and structured-output noisy. |
| `nvidia/nemotron-3-ultra-550b-a55b` | OK | 19 | 11 / 8 | 151,377 | 246.6s | 2 | 0 / 0 | 4 | Clean live probe and decent speed/yield, but extraction still needed repairs and enrichment fallbacks. |

## Qualitative Findings

Baseline strengths:

- Fastest wall-clock runtime.
- No timeout or recovery path.
- Good enough as the default throughput model.

Baseline weaknesses:

- Lowest finding count in this bake-off.
- Several enrichment calls returned reasoning text or failed capability JSON parsing.

Kimi strengths:

- Highest total findings.
- Found some extra high-value ideas, including citation cross-reference validation, disagreement scoring, privacy-preserving summary-only assist, and richer state-machine framing.

Kimi weaknesses:

- Timed out on the normal TypeScript prompt.
- Required content reduction from 1500KB to 750KB.
- Slowest by a large margin.
- Multiple reasoning-field and capability JSON fallback events.

GLM strengths:

- Strong finding count with similar token use to baseline.
- Good coverage of app-relevant patterns: DAG validation, cost ceilings, redaction, state machines, fetch injection, schema-versioned snapshots, and actionable fallback policy.
- No timeout or content-reduction recovery.

GLM weaknesses:

- Slower than baseline.
- Live probe did not obey `OK only` cleanly.
- Multiple malformed JSON repairs and capability parse fallbacks.

Nemotron strengths:

- Cleanest live probe among the candidate models.
- Better finding count than baseline.
- No timeout or content-reduction recovery.
- Found useful local-app/security ideas such as session-only API key handling and progressive verification gates.

Nemotron weaknesses:

- More structured-output repair/fallback events than ideal.
- Lower finding count than Kimi and GLM.
- Slower than baseline.

## Recommendation

Use `deepseek/deepseek-v4-flash` as the default CAM mining model for routine throughput.

Add `z-ai/glm-5.2` as the first experimental escalation candidate for deeper mines where more findings are worth a slower run.

Do not use `moonshotai/kimi-k2.7-code` as the default for large CAM mining prompts yet. It may be useful for targeted high-value repos, but this run shows timeout/recovery risk and high wall-clock cost.

Keep `nvidia/nemotron-3-ultra-550b-a55b` as a secondary candidate for clean probe behavior and moderate yield, but it did not beat GLM on this run.

## Next Test

Run the same bake-off on a second repo with different shape, preferably one security/redaction repo and one UI-heavy repo, before permanently changing CAM routing.
