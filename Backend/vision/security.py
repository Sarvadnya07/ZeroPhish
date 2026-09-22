"""
Image Security Validator & Pixel Decoder Boundary
==================================================
Strictly enforces pre-decoding guards:
- Magic bytes verification (PNG, JPEG, WebP, GIF)
- Size limits (max 7MB base64 string, max 5MB decoded bytes)
- Header-based dimension checks (width <= 4096, height <= 4096)
- Decompression bomb protection (max 16,000,000 pixels)

Separates pre-decode validation from actual pixel decoding (via Pillow with
hardened MAX_IMAGE_PIXELS limits).
"""

from __future__ import annotations

import base64
import io
import logging
import math
import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from PIL import Image

logger = logging.getLogger(__name__)

# Security thresholds
MAX_BASE64_LENGTH = 7_000_000       # ~5.25MB decoded
MIN_IMAGE_BYTES = 50                # Minimum header size
MAX_IMAGE_BYTES = 5_000_000         # 5MB max payload
MAX_DIMENSION = 4096                # Max width or height
MAX_PIXELS = 16_000_000             # 4096 x 4096 max resolution
Image.MAX_IMAGE_PIXELS = MAX_PIXELS # Harden PIL against decompression bombs


class ImageSecurityError(ValueError):
    """Raised when an image payload violates security boundaries."""
    pass


class UnsupportedImageFormatError(ImageSecurityError):
    """Raised when magic bytes do not match allowed formats."""
    pass


class ImageDecompressionBombError(ImageSecurityError):
    """Raised when dimensions or pixel count exceed safety limits."""
    pass


@dataclass(frozen=True)
class ValidatedImage:
    """Container for pre-decode validated image payload."""
    raw_bytes: bytes
    mime_type: str
    format_name: str
    width: int
    height: int
    size_bytes: int


@dataclass(frozen=True)
class DecodedPixelData:
    """Container for raw decoded pixel properties."""
    width: int
    height: int
    channels: int
    mean_luminance: float
    luminance_variance: float
    color_entropy: float
    edge_density: float


class ImageSecurityValidator:
    """
    Validates image binary structure BEFORE passing to decoders or external providers.
    Zero execution of lossy or vulnerable decompression code during validation.
    """

    @classmethod
    def validate_and_extract(cls, image_b64: str) -> ValidatedImage:
        """
        Validate base64 string, binary magic bytes, payload size, and header dimensions.
        """
        if not image_b64 or not isinstance(image_b64, str):
            raise ImageSecurityError("Empty or invalid image data string.")

        if len(image_b64) > MAX_BASE64_LENGTH:
            raise ImageSecurityError(
                f"Base64 image length ({len(image_b64)}) exceeds limit ({MAX_BASE64_LENGTH})."
            )

        # Strip Data URL scheme if present
        b64_payload = image_b64
        if "," in image_b64:
            header, b64_payload = image_b64.split(",", 1)
            b64_payload = b64_payload.strip()

        try:
            raw_bytes = base64.b64decode(b64_payload, validate=True)
        except Exception as e:
            raise ImageSecurityError(f"Base64 decoding failed: {e}") from e

        size_bytes = len(raw_bytes)
        if size_bytes < MIN_IMAGE_BYTES:
            raise ImageSecurityError(f"Image payload too small ({size_bytes} bytes).")
        if size_bytes > MAX_IMAGE_BYTES:
            raise ImageSecurityError(f"Image payload too large ({size_bytes} bytes > {MAX_IMAGE_BYTES}).")

        # Magic bytes and header dimension inspection
        fmt, mime, width, height = cls._inspect_headers(raw_bytes)

        if width > MAX_DIMENSION or height > MAX_DIMENSION:
            raise ImageDecompressionBombError(
                f"Image dimensions ({width}x{height}) exceed maximum allowed ({MAX_DIMENSION}x{MAX_DIMENSION})."
            )

        total_pixels = width * height
        if total_pixels > MAX_PIXELS:
            raise ImageDecompressionBombError(
                f"Image pixel count ({total_pixels}) exceeds maximum allowed ({MAX_PIXELS})."
            )

        return ValidatedImage(
            raw_bytes=raw_bytes,
            mime_type=mime,
            format_name=fmt,
            width=width,
            height=height,
            size_bytes=size_bytes,
        )

    @classmethod
    def _inspect_headers(cls, data: bytes) -> Tuple[str, str, int, int]:
        """
        Extract dimensions from binary header markers without decompressing pixel blocks.
        Supports PNG, JPEG, WebP, GIF.
        """
        # 1. PNG: \x89PNG\r\n\x1a\n
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            if len(data) < 24:
                raise ImageSecurityError("Truncated PNG header.")
            # IHDR chunk: offset 16 is width (4 bytes BE), offset 20 is height (4 bytes BE)
            width, height = struct.unpack(">II", data[16:24])
            return "PNG", "image/png", width, height

        # 2. JPEG: \xFF\xD8\xFF
        if data.startswith(b"\xFF\xD8\xFF"):
            width, height = cls._parse_jpeg_dimensions(data)
            return "JPEG", "image/jpeg", width, height

        # 3. WebP: RIFF....WEBP
        if data.startswith(b"RIFF") and len(data) >= 30 and data[8:12] == b"WEBP":
            width, height = cls._parse_webp_dimensions(data)
            return "WEBP", "image/webp", width, height

        # 4. GIF: GIF87a or GIF89a
        if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
            if len(data) < 10:
                raise ImageSecurityError("Truncated GIF header.")
            width, height = struct.unpack("<HH", data[6:10])
            return "GIF", "image/gif", width, height

        raise UnsupportedImageFormatError("Unrecognized or unsupported image binary format.")

    @staticmethod
    def _parse_jpeg_dimensions(data: bytes) -> Tuple[int, int]:
        """Scan JPEG markers to find SOF (Start of Frame) segment."""
        idx = 2
        length = len(data)
        while idx < length - 8:
            if data[idx] != 0xFF:
                idx += 1
                continue
            marker = data[idx + 1]
            # SOF0, SOF1, SOF2, etc. (0xC0 to 0xC3, 0xC5 to 0xC7, 0xC9 to 0xCB, 0xCD to 0xCF)
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                # SOF segment format:
                # [FF marker] [2-byte len] [1-byte precision] [2-byte height] [2-byte width]
                height, width = struct.unpack(">HH", data[idx + 5: idx + 9])
                return width, height
            # Skip marker segment
            idx += 2
            if idx + 2 <= length:
                seg_len = struct.unpack(">H", data[idx: idx + 2])[0]
                idx += seg_len
            else:
                break
        raise ImageSecurityError("Could not locate valid JPEG SOF segment.")

    @staticmethod
    def _parse_webp_dimensions(data: bytes) -> Tuple[int, int]:
        """Parse WebP dimensions from VP8, VP8L, or VP8X chunks."""
        chunk_type = data[12:16]
        if chunk_type == b"VP8 ":
            # Lossy VP8
            if len(data) < 30:
                raise ImageSecurityError("Truncated VP8 WebP header.")
            # Keyframe startcode 9D 01 2A at offset 23
            if data[23:26] == b"\x9d\x01\x2a":
                w, h = struct.unpack("<HH", data[26:30])
                return (w & 0x3FFF), (h & 0x3FFF)
        elif chunk_type == b"VP8L":
            # Lossless VP8L
            if len(data) < 25:
                raise ImageSecurityError("Truncated VP8L WebP header.")
            # 1-byte signature (0x2F), followed by 32-bit packed dimensions
            b0, b1, b2, b3 = data[21:25]
            width = 1 + (((b1 & 0x3F) << 8) | b0)
            height = 1 + (((b3 & 0x0F) << 10) | (b2 << 2) | ((b1 & 0xC0) >> 6))
            return width, height
        elif chunk_type == b"VP8X":
            # Extended WebP
            if len(data) < 30:
                raise ImageSecurityError("Truncated VP8X WebP header.")
            w_raw = struct.unpack("<I", data[24:28])[0] & 0xFFFFFF
            h_raw = struct.unpack("<I", data[27:31])[0] >> 8
            return (w_raw + 1), (h_raw + 1)

        raise ImageSecurityError("Unrecognized or unsupported WebP chunk format.")


class ImagePixelDecoder:
    """
    Decodes pre-validated image bytes into raw pixel data using hardened Pillow bounds.
    """

    @classmethod
    def decode(cls, validated: ValidatedImage) -> DecodedPixelData:
        """
        Safely open image, convert to RGB, and compute raw pixel forensic statistics.
        """
        try:
            with Image.open(io.BytesIO(validated.raw_bytes)) as img:
                img.verify()  # Integrity check

            # Re-open after verify() closes/invalidates descriptor
            with Image.open(io.BytesIO(validated.raw_bytes)) as img:
                rgb_img = img.convert("RGB")
                width, height = rgb_img.size

                # Sample pixel statistics efficiently
                pixels = list(rgb_img.get_flattened_data())
                total_count = len(pixels)
                if total_count == 0:
                    raise ImageSecurityError("Empty pixel buffer.")

                # Compute luminance: Y = 0.299R + 0.587G + 0.114B
                luminances = [0.299 * p[0] + 0.587 * p[1] + 0.114 * p[2] for p in pixels]
                mean_lum = sum(luminances) / total_count
                var_lum = sum((l - mean_lum) ** 2 for l in luminances) / total_count

                # Compute color entropy from 64-bin quantized palette
                hist: Dict[int, int] = {}
                for p in pixels:
                    bin_id = ((p[0] >> 6) << 4) | ((p[1] >> 6) << 2) | (p[2] >> 6)
                    hist[bin_id] = hist.get(bin_id, 0) + 1

                entropy = 0.0
                for count in hist.values():
                    p = count / total_count
                    if p > 0:
                        entropy -= p * math.log2(p)

                # High-frequency horizontal edge estimation (sample every 10th row)
                edge_diffs = 0.0
                sampled_transitions = 0
                step = max(1, height // 50)
                for y in range(0, height, step):
                    row_offset = y * width
                    for x in range(width - 1):
                        diff = abs(luminances[row_offset + x + 1] - luminances[row_offset + x])
                        edge_diffs += diff
                        sampled_transitions += 1

                mean_edge_density = edge_diffs / max(1, sampled_transitions)

                return DecodedPixelData(
                    width=width,
                    height=height,
                    channels=3,
                    mean_luminance=round(mean_lum, 2),
                    luminance_variance=round(var_lum, 2),
                    color_entropy=round(entropy, 3),
                    edge_density=round(mean_edge_density, 2),
                )
        except Exception as e:
            logger.error("Pixel decoding failed: %s", e)
            raise ImageSecurityError(f"Failed to decode image pixels: {e}") from e
