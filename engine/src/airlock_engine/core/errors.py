"""User-facing errors.

PRD §34: every error says what happened, whether the original file was
affected, and what the user can do next. Messages must never contain document
content, matched values or full file paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(eq=False)
class AirlockError(Exception):
    kind: str
    message: str
    next_step: str
    original_affected: bool = False

    def to_data(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "next_step": self.next_step,
            "original_affected": self.original_affected,
        }

    def __str__(self) -> str:
        return f"{self.kind}: {self.message}"


def file_not_found() -> AirlockError:
    return AirlockError(
        kind="file_not_found",
        message="Airlock could not find this file. It may have been moved or deleted.",
        next_step="Check the file still exists and drop it again.",
    )


def not_a_regular_file() -> AirlockError:
    return AirlockError(
        kind="not_a_file",
        message="This item is not a regular file, so Airlock cannot scan it.",
        next_step="Drop a document, spreadsheet, presentation, image or text file.",
    )


def file_unreadable() -> AirlockError:
    return AirlockError(
        kind="file_unreadable",
        message="Airlock does not have permission to read this file.",
        next_step="Close any program that has the file open, or copy it to a folder you own.",
    )


def file_too_large(limit_mb: int) -> AirlockError:
    return AirlockError(
        kind="file_too_large",
        message=f"This file is larger than the {limit_mb} MB limit for a single scan.",
        next_step="Split the file into smaller parts and scan each one.",
    )


def file_empty() -> AirlockError:
    return AirlockError(
        kind="file_empty",
        message="This file is empty, so there is nothing to scan.",
        next_step="Check you selected the right file.",
    )


def format_mismatch(extension: str, detected: str) -> AirlockError:
    return AirlockError(
        kind="format_mismatch",
        message=(
            f"This file is named .{extension} but its contents look like {detected}. "
            "Airlock will not process files whose contents do not match their type."
        ),
        next_step="Save the file again from the application that created it.",
    )


def unsupported_format(extension: str) -> AirlockError:
    shown = f".{extension}" if extension else "files without an extension"
    return AirlockError(
        kind="unsupported_format",
        message=f"Airlock does not support {shown} yet.",
        next_step="Convert the file to PDF, DOCX, XLSX, PPTX, CSV or TXT and try again.",
    )


def encrypted_document() -> AirlockError:
    return AirlockError(
        kind="encrypted_document",
        message="This document is password-protected, so Airlock cannot read its contents.",
        next_step="Remove the password in the original application, then scan the copy.",
    )


def internal_error() -> AirlockError:
    return AirlockError(
        kind="internal_error",
        message="The Airlock engine hit an unexpected problem and stopped this operation.",
        next_step="Try again. If it keeps happening, restart Airlock.",
    )
