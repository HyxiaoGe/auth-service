"""邮箱身份使用的唯一规范化规则。"""

from sqlalchemy import func


def normalize_email(email: str) -> str:
    """去除边界空白并进行大小写无关归一化。"""
    return email.strip().lower()


def normalized_email_expression(column):
    """返回与数据库唯一索引一致的规范化邮箱表达式。"""
    return func.lower(func.btrim(column))
