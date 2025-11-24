import re
import logging

class LogMonitor:
    def __init__(self):
        self.logger = logging.getLogger("LogMonitor")
        self.findings = []
        self.patterns = [
            (r"(?i)(signature|hash|checksum).*fail", "Verification Failure"),
            (r"(?i)loading\s*fallback", "Downgrade Attack Window"),
            (r"(?i)root\s*key", "Root of Trust Exposure")
        ]

    def analyze_line(self, line):
        """Analyzes a single line of log output."""
        for pattern, description in self.patterns:
            if re.search(pattern, line):
                finding = f"ALERT: {description} detected in log: '{line.strip()}'"
                self.logger.warning(finding)
                self.findings.append(finding)

    def analyze_stream(self, stream):
        """Analyzes a stream (like stdout) line by line."""
        # Note: This is a blocking call if the stream is blocking.
        # In a real scenario, this might run in a separate thread.
        for line in stream:
            self.analyze_line(line)

    def get_findings(self):
        return self.findings
