"""Secure Prompt: turn a plain code request into secure code, explained against the OWASP Top 10.

Online mode only (Gemini). One structured model call returns the code, the reasons it is safe and
the OWASP categories those reasons belong to. Nothing here runs or scans the generated code, so the
reasons are the model's claims, and every response says so.
"""

from aegis.secure_prompt.schemas import OWASP_2021, SecurePromptOut, SecurePromptRequest
from aegis.secure_prompt.service import SecurePromptUnavailable, generate

__all__ = ["OWASP_2021", "SecurePromptOut", "SecurePromptRequest", "SecurePromptUnavailable", "generate"]
