"""
GreyTab - AI agent integration helpers.
Provider-agnostic wrappers for LLM connection tests and finding verification.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

import httpx

SUPPORTED_PROVIDERS = {"openai", "anthropic", "gemini", "ollama", "custom"}
DEFAULT_PROVIDER = "ollama"


def default_ai_agent_config() -> Dict[str, Any]:
    """Return default AI integration configuration."""
    return {
        "enabled": False,
        "provider": DEFAULT_PROVIDER,
        "endpoint": "",
        "model": "",
        "api_key": "",
        "verify_findings": True,
        "timeout_seconds": 20,
        "temperature": 0.1,
        "review_scope": "ambiguous_or_high",
        "max_reviews_per_scan": 20,
        "cache_enabled": True,
    }


def normalize_ai_agent_config(raw: Optional[Dict[str, Any]], existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Normalize and merge AI settings from partial payloads."""
    base = default_ai_agent_config()
    if isinstance(existing, dict):
        base.update({k: existing.get(k) for k in base.keys() if k in existing})

    src = raw if isinstance(raw, dict) else {}

    provider = str(src.get("provider", base["provider"]) or base["provider"]).strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        provider = DEFAULT_PROVIDER

    endpoint = str(src.get("endpoint", base.get("endpoint", "")) or "").strip()
    model = str(src.get("model", base.get("model", "")) or "").strip()

    clear_api_key = bool(src.get("clear_api_key", False))
    incoming_key = src.get("api_key", None)
    if clear_api_key:
        api_key = ""
    elif isinstance(incoming_key, str) and incoming_key.strip():
        api_key = incoming_key.strip()
    else:
        api_key = str(base.get("api_key", "") or "")

    timeout_seconds = src.get("timeout_seconds", base.get("timeout_seconds", 20))
    try:
        timeout_seconds = int(timeout_seconds)
    except (TypeError, ValueError):
        timeout_seconds = 20
    timeout_seconds = max(5, min(timeout_seconds, 120))

    temperature = src.get("temperature", base.get("temperature", 0.1))
    try:
        temperature = float(temperature)
    except (TypeError, ValueError):
        temperature = 0.1
    temperature = max(0.0, min(temperature, 1.0))

    enabled = bool(src.get("enabled", base.get("enabled", False)))
    verify_findings = bool(src.get("verify_findings", base.get("verify_findings", True)))
    review_scope = str(src.get("review_scope", base.get("review_scope", "ambiguous_or_high")) or "ambiguous_or_high").strip().lower()
    if review_scope not in {"all", "ambiguous_or_high", "high_only"}:
        review_scope = "ambiguous_or_high"

    max_reviews_per_scan = src.get("max_reviews_per_scan", base.get("max_reviews_per_scan", 20))
    try:
        max_reviews_per_scan = int(max_reviews_per_scan)
    except (TypeError, ValueError):
        max_reviews_per_scan = 20
    max_reviews_per_scan = max(0, min(max_reviews_per_scan, 200))

    cache_enabled = bool(src.get("cache_enabled", base.get("cache_enabled", True)))

    return {
        "enabled": enabled,
        "provider": provider,
        "endpoint": endpoint,
        "model": model,
        "api_key": api_key,
        "verify_findings": verify_findings,
        "timeout_seconds": timeout_seconds,
        "temperature": temperature,
        "review_scope": review_scope,
        "max_reviews_per_scan": max_reviews_per_scan,
        "cache_enabled": cache_enabled,
    }


def mask_ai_agent_config(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a safe-to-send config object for UI (without raw API key)."""
    cfg = normalize_ai_agent_config(raw)
    key = cfg.get("api_key") or ""
    masked = cfg.copy()
    masked["api_key"] = ""
    masked["api_key_set"] = bool(key)
    masked["api_key_hint"] = f"***{key[-4:]}" if len(key) >= 4 else ("***" if key else "")
    return masked


class AIAgentError(Exception):
    """Raised when AI provider calls fail or return invalid data."""


class AIAgentClient:
    """Thin wrapper around provider-specific chat/generation APIs."""

    SYSTEM_PROMPT = (
        "You are a senior web security analyst. "
        "Classify whether a scanner finding is likely real or false positive. "
        "Do not claim deterministic confirmation. "
        "Only triage ambiguity and propose next technical tests. "
        "You must output JSON only."
    )

    def __init__(self):
        self._http = httpx.AsyncClient(verify=False)

    async def close(self):
        await self._http.aclose()

    async def test_connection(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a cheap prompt against the provider to validate connectivity and credentials."""
        prompt = (
            "Return strict JSON only: "
            '{"status":"ok","provider":"<provider>","message":"connected"}'
        )
        started = time.perf_counter()
        content = await self._invoke_provider(cfg, prompt, max_tokens=90)
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        provider = str(cfg.get("provider", "") or "").lower()
        data = _extract_json_obj(content)
        ok = bool(data)
        non_json_but_connected = False
        if not ok and provider == "ollama" and isinstance(content, str) and content.strip():
            # Ollama models may ignore strict JSON formatting in lightweight health checks.
            # Treat this as connectivity success, while warning about output format.
            ok = True
            non_json_but_connected = True
        return {
            "ok": ok,
            "latency_ms": elapsed_ms,
            "provider": cfg.get("provider", ""),
            "model": cfg.get("model", ""),
            "message": (
                "Connected (Ollama responded, but output was non-JSON)."
                if non_json_but_connected
                else ((data.get("message") if bool(data) else "Connected, but provider returned non-JSON output") or "connected")
            ),
            "raw_preview": content[:280],
            "non_json_output": bool(non_json_but_connected or (not bool(data))),
        }

    async def analyze_finding(self, cfg: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
        """Ask the model to triage a scanner finding and return a normalized verdict."""
        prompt = self._build_finding_prompt(finding)
        content = await self._invoke_provider(cfg, prompt, max_tokens=380)

        parsed = _extract_json_obj(content)
        if not parsed:
            return {
                "provider": cfg.get("provider", ""),
                "model": cfg.get("model", ""),
                "verdict": "needs_manual_review",
                "confidence": 0.35,
                "reasoning": "Provider did not return JSON in the expected format.",
                "follow_up_tests": ["Manual review required."],
            }

        verdict = str(parsed.get("verdict", "needs_manual_review")).strip().lower()
        if verdict not in {"confirmed", "likely_false_positive", "needs_manual_review"}:
            verdict = "needs_manual_review"

        confidence = parsed.get("confidence", 0.5)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(confidence, 1.0))

        reasoning = str(parsed.get("reasoning", "No reasoning provided.") or "No reasoning provided.").strip()
        if len(reasoning) > 1200:
            reasoning = reasoning[:1200]

        follow_up_tests = parsed.get("follow_up_tests")
        if not isinstance(follow_up_tests, list):
            follow_up_tests = []
        cleaned_followups: List[str] = []
        for item in follow_up_tests[:6]:
            text = str(item or "").strip()
            if text:
                cleaned_followups.append(text[:220])

        return {
            "provider": cfg.get("provider", ""),
            "model": cfg.get("model", ""),
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": reasoning,
            "follow_up_tests": cleaned_followups,
        }

    def _build_finding_prompt(self, finding: Dict[str, Any]) -> str:
        url = str(finding.get("url", ""))[:500]
        vuln_type = str(finding.get("vuln_type", ""))[:80]
        severity = str(finding.get("severity", ""))[:32]
        parameter = str(finding.get("parameter", ""))[:120]
        payload = str(finding.get("payload", ""))[:500]
        evidence = str(finding.get("evidence", ""))[:1800]
        request_raw = str(finding.get("request_raw", ""))[:2500]
        response_raw = str(finding.get("response_raw", ""))[:3500]
        feedback_hint = finding.get("feedback_hint")
        feedback_text = ""
        if isinstance(feedback_hint, dict):
            tp = int(feedback_hint.get("true_positive", 0) or 0)
            fp = int(feedback_hint.get("false_positive", 0) or 0)
            feedback_text = f"Historical analyst feedback for similar fingerprint: TP={tp}, FP={fp}."

        return (
            "Analyze this web security scanner finding.\n"
            "Goal: reduce false positives while avoiding missed true positives.\n\n"
            "Finding JSON:\n"
            f"{json.dumps({'url': url, 'vuln_type': vuln_type, 'severity': severity, 'parameter': parameter, 'payload': payload, 'evidence': evidence}, ensure_ascii=True)}\n\n"
            f"{feedback_text}\n\n"
            "Request excerpt:\n"
            f"{request_raw}\n\n"
            "Response excerpt:\n"
            f"{response_raw}\n\n"
            "Important: do not label a finding as technically confirmed. "
            "Use 'confirmed' only as 'likely valid' confidence signal for triage.\n\n"
            "Return strict JSON only with this exact schema:\n"
            '{"verdict":"confirmed|likely_false_positive|needs_manual_review","confidence":0.0,"reasoning":"short rationale","follow_up_tests":["step 1","step 2"]}'
        )

    async def _invoke_provider(self, cfg: Dict[str, Any], prompt: str, max_tokens: int = 300) -> str:
        provider = str(cfg.get("provider", "") or "").lower()
        timeout_s = float(cfg.get("timeout_seconds", 20) or 20)

        if provider not in SUPPORTED_PROVIDERS:
            raise AIAgentError(f"Unsupported provider: {provider}")

        if provider == "openai":
            return await self._call_openai(cfg, prompt, max_tokens=max_tokens, timeout_s=timeout_s)
        if provider == "anthropic":
            return await self._call_anthropic(cfg, prompt, max_tokens=max_tokens, timeout_s=timeout_s)
        if provider == "gemini":
            return await self._call_gemini(cfg, prompt, timeout_s=timeout_s)
        if provider == "ollama":
            return await self._call_ollama(cfg, prompt, timeout_s=timeout_s)
        return await self._call_custom(cfg, prompt, timeout_s=timeout_s)

    async def _call_openai(self, cfg: Dict[str, Any], prompt: str, max_tokens: int, timeout_s: float) -> str:
        endpoint = cfg.get("endpoint") or "https://api.openai.com/v1/chat/completions"
        model = cfg.get("model") or "gpt-4o-mini"
        key = str(cfg.get("api_key") or "").strip()
        if not key:
            raise AIAgentError("OpenAI API key is required")

        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "temperature": float(cfg.get("temperature", 0.1) or 0.1),
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        data = await self._post_json(endpoint, headers, payload, timeout_s)
        return _extract_openai_text(data)

    async def _call_anthropic(self, cfg: Dict[str, Any], prompt: str, max_tokens: int, timeout_s: float) -> str:
        endpoint = cfg.get("endpoint") or "https://api.anthropic.com/v1/messages"
        model = cfg.get("model") or "claude-3-5-sonnet-latest"
        key = str(cfg.get("api_key") or "").strip()
        if not key:
            raise AIAgentError("Anthropic API key is required")

        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": float(cfg.get("temperature", 0.1) or 0.1),
            "system": self.SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
        data = await self._post_json(endpoint, headers, payload, timeout_s)
        return _extract_anthropic_text(data)

    async def _call_gemini(self, cfg: Dict[str, Any], prompt: str, timeout_s: float) -> str:
        model = cfg.get("model") or "gemini-1.5-flash"
        key = str(cfg.get("api_key") or "").strip()

        endpoint = cfg.get("endpoint") or f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        if "{model}" in endpoint:
            endpoint = endpoint.replace("{model}", model)

        if not key:
            raise AIAgentError("Gemini API key is required")

        join_char = "&" if "?" in endpoint else "?"
        if "key=" not in endpoint:
            endpoint = f"{endpoint}{join_char}key={key}"

        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{self.SYSTEM_PROMPT}\n\n{prompt}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": float(cfg.get("temperature", 0.1) or 0.1),
            },
        }
        data = await self._post_json(endpoint, headers, payload, timeout_s)
        return _extract_gemini_text(data)

    async def _call_ollama(self, cfg: Dict[str, Any], prompt: str, timeout_s: float) -> str:
        endpoint = cfg.get("endpoint") or "http://127.0.0.1:11434/api/generate"
        if endpoint.endswith("/"):
            endpoint = endpoint[:-1]
        if endpoint.endswith(":11434") or not endpoint.endswith("/api/generate"):
            endpoint = endpoint + "/api/generate" if not endpoint.endswith("/api/generate") else endpoint

        model = cfg.get("model") or "llama3.1:8b"

        payload = {
            "model": model,
            "prompt": f"{self.SYSTEM_PROMPT}\n\n{prompt}",
            "stream": False,
            "format": "json",
            "options": {
                "temperature": float(cfg.get("temperature", 0.1) or 0.1),
            },
        }
        data = await self._post_json(endpoint, {"Content-Type": "application/json"}, payload, timeout_s)
        text = data.get("response")
        if not isinstance(text, str) or not text.strip():
            raise AIAgentError("Ollama response did not contain a text payload")
        return text

    async def _call_custom(self, cfg: Dict[str, Any], prompt: str, timeout_s: float) -> str:
        endpoint = str(cfg.get("endpoint") or "").strip()
        if not endpoint:
            raise AIAgentError("Custom provider requires an endpoint URL")

        headers = {"Content-Type": "application/json"}
        key = str(cfg.get("api_key") or "").strip()
        if key:
            headers["Authorization"] = f"Bearer {key}"

        payload = {
            "provider": "custom",
            "model": cfg.get("model") or "",
            "system": self.SYSTEM_PROMPT,
            "prompt": prompt,
            "temperature": float(cfg.get("temperature", 0.1) or 0.1),
            "format": "json",
        }
        data = await self._post_json(endpoint, headers, payload, timeout_s)

        for candidate_key in ("content", "text", "output", "response", "result"):
            val = data.get(candidate_key)
            if isinstance(val, str) and val.strip():
                return val
        return json.dumps(data, ensure_ascii=True)

    async def _post_json(self, endpoint: str, headers: Dict[str, str], payload: Dict[str, Any], timeout_s: float) -> Dict[str, Any]:
        try:
            resp = await self._http.post(endpoint, headers=headers, json=payload, timeout=timeout_s)
        except Exception as exc:
            raise AIAgentError(f"Connection failed: {exc}") from exc

        if resp.status_code >= 400:
            text = resp.text[:400]
            raise AIAgentError(f"Provider returned {resp.status_code}: {text}")

        try:
            return resp.json()
        except Exception as exc:
            raise AIAgentError(f"Invalid JSON response from provider: {exc}") from exc


def _extract_openai_text(data: Dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise AIAgentError("OpenAI response missing choices")

    msg = choices[0].get("message", {})
    content = msg.get("content")
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                txt = part.get("text")
                if isinstance(txt, str):
                    parts.append(txt)
        if parts:
            return "\n".join(parts)

    raise AIAgentError("OpenAI response did not include textual content")


def _extract_anthropic_text(data: Dict[str, Any]) -> str:
    content = data.get("content")
    if not isinstance(content, list) or not content:
        raise AIAgentError("Anthropic response missing content")

    parts = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            txt = block.get("text")
            if isinstance(txt, str):
                parts.append(txt)

    if not parts:
        raise AIAgentError("Anthropic response did not include text blocks")
    return "\n".join(parts)


def _extract_gemini_text(data: Dict[str, Any]) -> str:
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise AIAgentError("Gemini response missing candidates")

    parts = candidates[0].get("content", {}).get("parts", [])
    if not isinstance(parts, list):
        raise AIAgentError("Gemini response has invalid content parts")

    texts = []
    for part in parts:
        if isinstance(part, dict):
            txt = part.get("text")
            if isinstance(txt, str):
                texts.append(txt)
    if not texts:
        raise AIAgentError("Gemini response did not include text")
    return "\n".join(texts)


def _extract_json_obj(text: str) -> Dict[str, Any]:
    """Extract a JSON object from a model response.

    Models sometimes wrap JSON in markdown fences or prose. This tries direct parse,
    fenced JSON parse, and first-brace/last-brace extraction.
    """
    if not isinstance(text, str):
        return {}

    clean = text.strip()
    if not clean:
        return {}

    # Direct JSON object
    try:
        parsed = json.loads(clean)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # JSON inside fenced block
    fenced = re.findall(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", clean, flags=re.IGNORECASE)
    for candidate in fenced:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue

    # First { ... last }
    first = clean.find("{")
    last = clean.rfind("}")
    if first != -1 and last != -1 and first < last:
        snippet = clean[first:last + 1]
        try:
            parsed = json.loads(snippet)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}

    return {}
