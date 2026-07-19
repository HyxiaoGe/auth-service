"""邮箱身份使用的唯一规范化规则。"""

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import func


def normalize_email(email: str) -> str:
    """转为与 PostgreSQL 唯一索引可严格对齐的 ASCII 规范邮箱。

    本地部分禁止 SMTPUTF8，Unicode 域名则转换为 IDNA。最终存储值只含
    ASCII，因此 Python 小写与数据库 ``lower(btrim(email))`` 不会出现 Unicode
    折叠差异。
    """
    try:
        validated = validate_email(
            email.strip(),
            allow_smtputf8=False,
            check_deliverability=False,
        )
    except (AttributeError, EmailNotValidError, UnicodeError) as error:
        raise ValueError("invalid canonical email") from error
    if validated.ascii_email is None:
        raise ValueError("invalid canonical email")
    return validated.ascii_email.lower()


def normalized_email_expression(column):
    """返回与数据库唯一索引一致的规范化邮箱表达式。"""
    return func.lower(func.btrim(column))
