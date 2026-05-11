"""
Variant hunting phase.

For each verified finding, generates grep patterns and semantic
descriptions, searches the codebase for structural matches, and
surfaces each as a variant finding. Runs up to 3 iterations —
each pass's new seeds feed the next pass's pattern generation.
"""

import re
import os
from mantis.engage.phases import Phase
from mantis.core.findings import Finding, FindingSource, EvidenceLevel


class VariantHunter:
    """Search codebase for variants of verified findings."""

    def find_variants(self, finding: Finding, source_files: list[dict]) -> list[Finding]:
        """Find code patterns similar to a verified finding."""
        variants = []
        if not finding.vuln_type or not finding.file_path:
            return variants

        # Generate search patterns based on the finding type
        patterns = self._generate_patterns(finding)

        for file_meta in source_files:
            filepath = file_meta.get("full_path", "")
            if filepath == finding.file_path:
                continue  # Skip the original file

            try:
                with open(filepath, "r", errors="replace") as f:
                    content = f.read()

                for pattern, description in patterns:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count("\n") + 1
                        variants.append(Finding(
                            title=f"Variant of {finding.id}: {description}",
                            description=f"Similar pattern to {finding.title} found at {file_meta['path']}:{line_num}",
                            source=FindingSource.CODE_REVIEW,
                            severity=finding.severity,
                            evidence_level=EvidenceLevel.SUSPICION,
                            file_path=file_meta["path"],
                            line_number=line_num,
                            vuln_type=finding.vuln_type,
                            cwe=finding.cwe,
                            variant_of=finding.id,
                            confidence=0.4,
                            tags=["variant", f"variant_of:{finding.id}"],
                        ))
                        break  # One variant per file per pattern
            except Exception:
                continue

        return variants

    def _generate_patterns(self, finding: Finding) -> list[tuple[str, str]]:
        """Generate regex patterns to find variants of a finding."""
        patterns = []
        vuln_type = finding.vuln_type.lower()

        if "sqli" in vuln_type or "sql" in vuln_type:
            patterns.append((r'\.execute\s*\([^)]*[+%]', "SQL execute with string formatting"))
            patterns.append((r'\.raw\s*\([^)]*[+%\{]', "ORM raw query with interpolation"))
            patterns.append((r'f["\'].*SELECT.*\{', "f-string SQL query"))

        elif "xss" in vuln_type:
            patterns.append((r'\.innerHTML\s*=', "innerHTML assignment"))
            patterns.append((r'mark_safe\s*\(', "mark_safe without sanitization"))
            patterns.append((r'dangerouslySetInnerHTML', "React dangerous HTML"))
            patterns.append((r'\|\s*safe\b', "Template safe filter"))

        elif "command" in vuln_type or "cmdi" in vuln_type:
            patterns.append((r'os\.system\s*\(', "os.system call"))
            patterns.append((r'subprocess.*shell\s*=\s*True', "subprocess with shell=True"))
            patterns.append((r'exec\s*\([^)]*\+', "exec with concatenation"))

        elif "ssti" in vuln_type or "template" in vuln_type:
            patterns.append((r'render_template_string\s*\(', "render_template_string"))
            patterns.append((r'Template\s*\([^)]*\+', "Template with user input"))
            patterns.append((r'\.from_string\s*\(', "Template from_string"))

        elif "path" in vuln_type or "traversal" in vuln_type or "lfi" in vuln_type:
            patterns.append((r'open\s*\([^)]*\+', "open() with concatenation"))
            patterns.append((r'os\.path\.join\s*\([^)]*request', "path.join with request data"))
            patterns.append((r'send_file\s*\([^)]*\+', "send_file with user input"))

        elif "deserializ" in vuln_type:
            patterns.append((r'pickle\.loads?\s*\(', "pickle deserialization"))
            patterns.append((r'yaml\.load\s*\(', "yaml.load (unsafe)"))
            patterns.append((r'json\.loads?\s*\(.*request', "JSON deserialization of request data"))

        return patterns


class VariantHuntPhase(Phase):
    """Phase: hunt for variants of verified findings."""

    async def execute(self, context) -> dict:
        verified = [f for f in context.findings
                    if f.verified and f.source == FindingSource.CODE_REVIEW]
        if not verified:
            print("    No verified findings to hunt variants for")
            return {}

        hunter = VariantHunter()
        all_variants = []

        for iteration in range(3):  # Up to 3 iterations
            seeds = verified if iteration == 0 else all_variants[-10:]  # Use recent variants as seeds
            new_variants = []
            for finding in seeds:
                variants = hunter.find_variants(finding, context.source_files)
                new_variants.extend(variants)

            if not new_variants:
                break
            all_variants.extend(new_variants)
            print(f"    Iteration {iteration + 1}: found {len(new_variants)} variants")

        # Deduplicate
        seen = set()
        unique = []
        for v in all_variants:
            key = f"{v.file_path}:{v.line_number}:{v.vuln_type}"
            if key not in seen:
                seen.add(key)
                unique.append(v)

        print(f"    Total unique variants: {len(unique)}")
        return {"findings": unique}
