"""口令哈希 —— Argon2id(OWASP 首选、PHC 冠军算法)。

为什么是 Argon2id:抗 GPU/ASIC 并行爆破(内存硬),同时抵御侧信道(id 变体融合
Argon2i 的抗侧信道与 Argon2d 的抗 GPU)。盐由库自动生成并编码进哈希串,无需另存。

存储的是自描述哈希串(含算法、参数、盐、摘要),校验时按串内参数重算;调参后旧串仍可校验,
并通过 `needs_rehash` 标记"该用更强参数重存了"。明文口令只在内存中短暂存在,绝不落库、绝不入日志。
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# 参数取 OWASP 2024 建议基线:64 MiB 内存、3 轮、并行度 4。
# 内存成本是抗爆破的主力;政企单机部署内存充裕,可在 .env 之外按硬件上调。
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain: str) -> str:
    """把明文口令哈希为自描述 Argon2id 串(含盐与参数)。"""
    return _HASHER.hash(plain)


def verify_password(stored_hash: str, plain: str) -> bool:
    """常数级时间校验;不匹配 / 串损坏一律返回 False,不抛栈泄露信息。"""
    try:
        return _HASHER.verify(stored_hash, plain)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """库内哈希参数低于当前基线时返回 True —— 调用方应在校验通过后用新参数重存。"""
    try:
        return _HASHER.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
