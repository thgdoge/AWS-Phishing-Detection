"""Chuẩn hóa văn bản để so khớp từ khóa tiếng Việt có dấu lẫn không dấu."""
import re
import unicodedata

_INVISIBLE = dict.fromkeys(map(ord, '\u200b\u200c\u200d\u2060\ufeff\u00ad'), None)


def fold(text: str) -> str:
    """Bỏ ký tự vô hình, bỏ dấu tiếng Việt (kể cả đ), đưa về chữ thường."""
    text = unicodedata.normalize('NFKD', (text or '').translate(_INVISIBLE))
    text = ''.join(ch for ch in text if not unicodedata.combining(ch))
    return text.replace('đ', 'd').replace('Đ', 'D').lower()


def word_pattern(phrase: str) -> 're.Pattern':
    """Regex khớp nguyên cụm từ (ranh giới từ), không khớp 'pin' trong 'shipping'."""
    return re.compile(r'(?<![a-z0-9])' + re.escape(phrase) + r'(?![a-z0-9])')
