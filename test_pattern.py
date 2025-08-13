#!/usr/bin/env python3

from dataclasses import dataclass

@dataclass
class WatchlistPattern:
    """Represents a pattern to watch for in the public key."""
    pattern: str  # e.g., "ABCD...EFGH" or "ABCD...ABCDEFGH"
    description: str  # Optional description
    first_chars: str  # First part of pattern
    last_chars: str   # Last part of pattern
    first_length: int  # Length of first part
    last_length: int   # Length of last part
    
    @classmethod
    def from_string(cls, pattern_str: str, description: str = "") -> 'WatchlistPattern':
        """Create a WatchlistPattern from a string like 'ABCD...EFGH'."""
        if '...' not in pattern_str:
            raise ValueError(f"Invalid pattern format: {pattern_str}. Must contain '...'")
        
        parts = pattern_str.split('...')
        if len(parts) != 2:
            raise ValueError(f"Invalid pattern format: {pattern_str}. Must have exactly one '...'")
        
        first_part = parts[0].strip()
        last_part = parts[1].strip()
        
        if not first_part or not last_part:
            raise ValueError(f"Invalid pattern format: {pattern_str}. Both parts must be non-empty")
        
        # Validate hex characters
        try:
            int(first_part, 16)
            int(last_part, 16)
        except ValueError:
            raise ValueError(f"Invalid pattern format: {pattern_str}. Parts must be valid hex")
        
        return cls(
            pattern=pattern_str,
            description=description,
            first_chars=first_part.upper(),
            last_chars=last_part.upper(),
            first_length=len(first_part),
            last_length=len(last_part)
        )
    
    def matches(self, public_hex: str) -> bool:
        """Check if a public key matches this pattern."""
        public_hex = public_hex.upper()
        first_match = public_hex[:self.first_length] == self.first_chars
        last_match = public_hex[-self.last_length:] == self.last_chars
        result = first_match and last_match
        
        print(f"Pattern: {self.pattern}")
        print(f"  Public key: {public_hex}")
        print(f"  First {self.first_length} chars: '{public_hex[:self.first_length]}' vs '{self.first_chars}' -> {first_match}")
        print(f"  Last {self.last_length} chars: '{public_hex[-self.last_length:]}' vs '{self.last_chars}' -> {last_match}")
        print(f"  Result: {result}")
        print()
        
        return result

# Test with the key we found
test_key = "aad3c37302d55ba3b0c194458d048721d0342d6af626b5a0baa99f7a63793daa"
print(f"Testing key: {test_key}")
print(f"First 8 chars: {test_key[:8]}")
print(f"Last 8 chars: {test_key[-8:]}")
print()

# Test the specific pattern 5A...5A5A5A5A
print("=== Testing 5A...5A5A5A5A pattern ===")
pattern = WatchlistPattern.from_string("5A...5A5A5A5A", "Test pattern")
pattern.matches(test_key)

# Test with a key that should match 5A...5A5A5A5A
test_key_5a = "5A1234567890ABCDEF1234567890ABCDEF5A5A5A5A"
print(f"\nTesting key that should match 5A...5A5A5A5A: {test_key_5a}")
print(f"First 2 chars: {test_key_5a[:2]}")
print(f"Last 8 chars: {test_key_5a[-8:]}")
pattern.matches(test_key_5a)

# Test some other patterns
patterns_to_test = [
    "AA...AAAAAAAA",
    "AA...AA",
    "AA...AAAA",
    "AAAA...AA",
    "AAAAAAAA...AA",
    "5A...5A5A5A5A"
]

for pattern_str in patterns_to_test:
    try:
        pattern = WatchlistPattern.from_string(pattern_str)
        pattern.matches(test_key)
    except Exception as e:
        print(f"Error with pattern {pattern_str}: {e}")
        print()
