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


# --- extraction (Phase 2) ---------------------------------------------------


def extraction_failed(format_label: str) -> AirlockError:
    return AirlockError(
        kind="extraction_failed",
        message=(
            f"Airlock could not read this {format_label}. The file may be damaged "
            "or use features Airlock does not support."
        ),
        next_step=(
            "Open the file in the application that created it, save a new copy, and scan that."
        ),
    )


def content_too_large(what: str) -> AirlockError:
    return AirlockError(
        kind="content_too_large",
        message=f"This file contains {what}, which is more than Airlock can scan at once.",
        next_step="Split it into smaller files and scan each one.",
    )


def extraction_timeout() -> AirlockError:
    return AirlockError(
        kind="extraction_timeout",
        message="Reading this file took too long, so Airlock stopped.",
        next_step="Try again, or split the file into smaller parts.",
    )


def extraction_crashed() -> AirlockError:
    return AirlockError(
        kind="extraction_crashed",
        message=(
            "Airlock's document reader stopped unexpectedly on this file. The file may be "
            "damaged, or crafted to attack document readers."
        ),
        next_step=(
            "Save a fresh copy from the application that created it, or scan a different copy."
        ),
    )


def resource_limit() -> AirlockError:
    return AirlockError(
        kind="resource_limit",
        message="This file needed more memory than Airlock allows for a single document.",
        next_step="Split the file into smaller parts and scan each one.",
    )


def unsafe_archive() -> AirlockError:
    return AirlockError(
        kind="unsafe_archive",
        message=(
            "This file is packaged in a way that expands to an unsafe size when opened "
            "(a 'zip bomb'). Airlock stopped reading it."
        ),
        next_step="Do not open this file. If you trust its source, ask the sender for a new copy.",
    )


# --- detection and rules (Phase 3) ------------------------------------------


def invalid_rule(message: str) -> AirlockError:
    return AirlockError(
        kind="invalid_rule",
        message=message,
        next_step="Edit the rule and save it again.",
    )


def rule_not_found() -> AirlockError:
    return AirlockError(
        kind="rule_not_found",
        message="This company rule no longer exists. It may have been deleted.",
        next_step="Refresh the list of rules.",
    )


def scan_not_found() -> AirlockError:
    return AirlockError(
        kind="scan_not_found",
        message="The results of this scan are no longer available. Airlock keeps them only "
        "for a limited time and never saves them to disk.",
        next_step="Scan the file again.",
    )


def storage_unavailable() -> AirlockError:
    return AirlockError(
        kind="storage_unavailable",
        message="Airlock could not open its settings database, so company rules are not "
        "available right now.",
        next_step="Restart Airlock. If it keeps happening, check that your user profile "
        "folder is writable.",
    )


# --- policy (Phase 4) -------------------------------------------------------


def profile_not_found() -> AirlockError:
    return AirlockError(
        kind="profile_not_found",
        message="This privacy profile no longer exists. It may have been deleted.",
        next_step="Choose another profile.",
    )


def invalid_profile(message: str) -> AirlockError:
    return AirlockError(
        kind="invalid_profile", message=message, next_step="Adjust the profile and try again."
    )


def finding_not_found() -> AirlockError:
    return AirlockError(
        kind="finding_not_found",
        message="One of these findings is not part of this scan.",
        next_step="Scan the file again.",
    )


def confirmation_required() -> AirlockError:
    return AirlockError(
        kind="confirmation_required",
        message="You chose to keep a critical finding, such as a password, key or "
        "national id. It would be shared with the AI as it is.",
        next_step="Confirm that you want to keep it, or choose mask, redact or block.",
    )


# --- masking and vault (Phase 5) --------------------------------------------


def blocked_findings(count: int) -> AirlockError:
    noun = "item is" if count == 1 else "items are"
    return AirlockError(
        kind="blocked_findings",
        message=f"{count} {noun} still set to Block, so Airlock will not create a protected "
        "copy yet.",
        next_step="Choose Redact or Mask for the blocked items, or remove them from the file.",
    )


def artifact_not_found() -> AirlockError:
    return AirlockError(
        kind="artifact_not_found",
        message="This protected copy is no longer available. Airlock keeps copies only until "
        "they are saved or discarded.",
        next_step="Create the protected copy again.",
    )


def vault_record_not_found() -> AirlockError:
    return AirlockError(
        kind="vault_record_not_found",
        message="Airlock has no stored placeholders for this protected copy. They may have "
        "expired or been deleted.",
        next_step="Placeholders can only be restored on the device that created the copy, "
        "within the retention period.",
    )


def vault_unavailable() -> AirlockError:
    return AirlockError(
        kind="vault_unavailable",
        message="Airlock could not open its encrypted placeholder store.",
        next_step="Restart Airlock. If it keeps happening, check that your user profile "
        "folder is writable.",
    )
