"""Shared Office Open XML (DOCX/XLSX/PPTX) package reading and text walking.

Airlock reads OOXML parts directly instead of through a high-level document
library so that *every* part is visited: comments, tracked changes, notes,
hidden sheets, pivot caches, properties, custom XML and embedded files.
"""
