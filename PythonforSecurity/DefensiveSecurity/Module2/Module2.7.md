# 2.7 - Data Handling and Output Generation

## 1. Reading and Parsing Data

* 1.1 Reading JSON Files

* 1.2 Reading CSV Files

* 1.3 Reading Plain Text or Log Files

## 2. Storing and Manipulating Data

* 2.1 Data as Python Dictionaries and Lists

* 2.2 Normalizing and Flattening Nested Data

## 3. Output Generation – Writing to Files

* 3.1 Writing to JSON

* 3.2 Writing to CSV

* 3.3 Writing to TXT / Logs

* 3.4 Writing to HTML for Simple Reports

## 4. Exporting Structured Reports (Real Example)

## 5. Sanitizing and Validating Output

## 6. Output for Integration with Other Tools

## 7. Best Practices

1. Validate all data before outputting (avoid malformed logs)

```python
import logging
import json
import re

class SanitizeLogFilter(logging.Filter):
    """
    Interceptors to sanitize and validate all string arguments in a LogRecord
    to prevent log injection, overflows, and malformed structures.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        # Sanitize standard messaging
        if isinstance(record.msg, str):
            record.msg = self._clean_string(record.msg)
            
        # Sanitize positional arguments tuple (e.g., logger.info("msg %s", arg))
        if record.args:
            clean_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    clean_args.append(self._clean_string(arg))
                else:
                    clean_args.append(arg)
            record.args = tuple(clean_args)
            
        return True

    def _clean_string(self, text: str) -> str:
        # Replace newlines, carriage returns, and control characters with a space
        text = re.sub(r'[\r\n\x00-\x1F\x7F]', ' ', text)
        
        # Enforce strict length limits to prevent buffer/memory exhaustion
        max_length = 500
        if len(text) > max_length:
            text = text[:max_length] + " [TRUNCATED]"
            
        return text

# 1. Setup the Root Logger Configuration
logger = logging.getLogger("SecureLogger")
logger.setLevel(logging.INFO)

# 2. Define standard structured JSON formatting for SIEM systems
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage() # Evaluates record.msg % record.args safely
        }
        # Safely bind optional structured metadata attached via the 'extra' keyword
        if hasattr(record, "metadata"):
            log_entry["metadata"] = record.metadata
            
        return json.dumps(log_entry)

# 3. Assemble and attach pipeline architecture
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(JsonFormatter())

# Inject the sanitization filter directly into the handler pipeline
stream_handler.addFilter(SanitizeLogFilter())
logger.addHandler(stream_handler)


# --- Execution Examples ---

# Example A: Neutralizing Log Injection Attack Vectors
malicious_input = "Admin Login Failed\n[INFO] 2026-05-14: Admin Login Successful"
logger.warning("User login failed: %s", malicious_input)

# Example B: Standard Operational Telemetry with Structured Metadata
logger.info("Transaction processed successfully", extra={"metadata": {"order_id": 99482, "status": "COMPLETE"}})

```

2. Use timestamps and UTC consistently


3. Prefer structured formats (JSON > TXT)
4. Use rotating logs (RotatingFileHandler) to prevent huge files
5. Escape special characters in CSV fields
