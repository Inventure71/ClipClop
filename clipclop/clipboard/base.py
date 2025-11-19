from abc import ABC, abstractmethod
from typing import Tuple, Optional

class ClipboardProvider(ABC):
    @abstractmethod
    def get_text(self) -> str:
        """Get text content from clipboard."""
        pass

    @abstractmethod
    def set_text(self, text: str) -> bool:
        """Set text content to clipboard."""
        pass

    @abstractmethod
    def get_image(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Get image from clipboard.
        Returns: (base64_data, format_string) or (None, None)
        """
        pass

    @abstractmethod
    def set_image(self, base64_data: str, format_hint: str = "png") -> bool:
        """Set image to clipboard."""
        pass

