import functools
import time
from typing import Callable, TypeVar

from loguru import logger

T = TypeVar("T")


def retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exceptions: tuple = (Exception,),
):
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    delay = min(base_delay * (2**attempt), max_delay)
                    logger.warning(
                        f"{func.__name__} attempt {attempt + 1}/{max_retries} failed: {e}, "
                        f"retrying in {delay:.1f}s"
                    )
                    time.sleep(delay)
            raise last_exception

        return wrapper

    return decorator
