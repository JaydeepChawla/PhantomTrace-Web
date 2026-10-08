"""
PhantomTrace Threat Scoring Engine
PhantomTrace Windows Release 1.0

Final Context-Aware Threat Scoring

Design:
- Memory anomalies are evidence, not proof of malware.
- Normal applications can legitimately contain executable/private memory.
- Behavioral evidence and memory evidence are correlated.
- Trusted/common applications receive conservative memory-only treatment.
- Behavioral evidence is NEVER suppressed by the memory-only cap.
- Correlated behavior + memory can escalate the score.
- Original evidence is preserved.
- Scanner remains completely read-only.
"""

from typing import Any, Dict, List


# ============================================================
# SCORE WEIGHTS
# ============================================================

BEHAVIOR_WEIGHTS = {
    "SUSPICIOUS_COMMAND_LINE": 15,
    "SUSPICIOUS_PARENT": 20,
    "SUSPICIOUS_CHILD": 15,
    "SUSPICIOUS_NETWORK": 20,
    "PERSISTENCE_INDICATOR": 25,
    "FILELESS_INDICATOR": 30,

    # Interpreter activity by itself is weak evidence.
    "SCRIPT_INTERPRETER_ACTIVITY": 5,

    "SUSPICIOUS_SCRIPT_CONTEXT": 10,
    "SUSPICIOUS_EXECUTION_CONTEXT": 15,
}


# ============================================================
# MEMORY WEIGHTS
# ============================================================

MEMORY_WEIGHTS = {
    "EXECUTABLE_WRITABLE_MEMORY": 15,
    "PRIVATE_EXECUTABLE_MEMORY": 10,
    "SUSPICIOUS_MEMORY_REGION": 15,
}


# ============================================================
# CORRELATION WEIGHTS
# ============================================================

CORRELATION_WEIGHTS = {
    "BEHAVIOR_MEMORY_CORRELATION": 10,
    "SCRIPT_MEMORY_CORRELATION": 15,
    "PARENT_MEMORY_CORRELATION": 10,
}


# ============================================================
# COMMON / TRUSTED APPLICATION CONTEXT
# ============================================================

COMMON_APPLICATIONS = {
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "code.exe",
    "explorer.exe",
    "svchost.exe",
    "searchapp.exe",
    "applicationframehost.exe",
    "runtimebroker.exe",
    "taskhostw.exe",
    "phoneexperiencehost.exe",
    "whatsapp.root.exe",
    "onlinent.exe",
}


# ============================================================
# FINAL SCORE LIMITS
# ============================================================

TOTAL_SCORE_CAP = 100.0

# Important:
# This is ONLY a final-score cap for trusted/common
# applications when the evidence is memory-only.
#
# The underlying memory evidence remains untouched.
MEMORY_ONLY_TRUSTED_CAP = 20.0

# Maximum memory contribution.
MEMORY_SCORE_CAP = 60.0

# Maximum behavior contribution.
BEHAVIOR_SCORE_CAP = 50.0

# Maximum process contribution.
PROCESS_SCORE_CAP = 25.0

# Maximum correlation contribution.
CORRELATION_CAP = 35.0


# ============================================================
# LEVEL MAPPING
# ============================================================

def score_to_level(score: float) -> str:
    """
    Convert numeric score to PhantomTrace threat level.
    """

    score = float(score)

    if score <= 0:
        return "NORMAL"

    if score < 25:
        return "LOW"

    if score < 50:
        return "MEDIUM"

    if score < 75:
        return "HIGH"

    return "CRITICAL"


# ============================================================
# NORMALIZATION HELPERS
# ============================================================

def _safe_list(value: Any) -> List[str]:
    """
    Safely convert a list-like value into a list of strings.
    """

    if not isinstance(value, list):
        return []

    return [
        str(item)
        for item in value
        if item is not None
    ]


def _safe_int(value: Any) -> int:
    """
    Safely convert a value to int.
    """

    try:
        return int(value)

    except (
        TypeError,
        ValueError,
    ):
        return 0


def _safe_float(value: Any) -> float:
    """
    Safely convert a value to float.
    """

    try:
        return float(value)

    except (
        TypeError,
        ValueError,
    ):
        return 0.0


# ============================================================
# APPLICATION CONTEXT
# ============================================================

def get_application_context(
    process_name: str,
) -> str:
    """
    Determine application context.

    This is contextual information, NOT an allowlist.
    """

    normalized_name = (
        str(process_name or "")
        .strip()
        .lower()
    )

    if normalized_name in COMMON_APPLICATIONS:
        return "TRUSTED_COMMON_APPLICATION"

    return "STANDARD_PROCESS"


# ============================================================
# MEMORY EVIDENCE DETECTION
# ============================================================

def has_memory_evidence(
    memory_result: Dict[str, Any],
) -> bool:
    """
    Determine whether memory evidence exists.

    This does not modify the evidence.
    """

    if not isinstance(
        memory_result,
        dict,
    ):
        return False

    indicators = _safe_list(
        memory_result.get(
            "indicators",
            [],
        )
    )

    suspicious_regions = _safe_int(
        memory_result.get(
            "suspicious_regions",
            0,
        )
    )

    rwx_regions = _safe_int(
        memory_result.get(
            "writable_executable_regions",
            0,
        )
    )

    private_exec_regions = _safe_int(
        memory_result.get(
            "private_executable_regions",
            0,
        )
    )

    return bool(
        indicators
        or suspicious_regions > 0
        or rwx_regions > 0
        or private_exec_regions > 0
    )


# ============================================================
# MEMORY SCORING
# ============================================================

def calculate_memory_score(
    memory_result: Dict[str, Any],
    process_name: str = "",
) -> Dict[str, Any]:
    """
    Calculate conservative memory evidence.

    Memory evidence is retained independently from the
    final threat score.
    """

    if not isinstance(
        memory_result,
        dict,
    ):
        return {
            "score": 0.0,
            "indicators": [],
            "evidence_strength": "NONE",
            "suspicious_regions": 0,
            "writable_executable_regions": 0,
            "private_executable_regions": 0,
        }

    memory_indicators = _safe_list(
        memory_result.get(
            "indicators",
            [],
        )
    )

    suspicious_regions = _safe_int(
        memory_result.get(
            "suspicious_regions",
            0,
        )
    )

    rwx_regions = _safe_int(
        memory_result.get(
            "writable_executable_regions",
            0,
        )
    )

    private_exec_regions = _safe_int(
        memory_result.get(
            "private_executable_regions",
            0,
        )
    )

    normalized_name = (
        str(process_name or "")
        .strip()
        .lower()
    )

    has_rwx = rwx_regions > 0
    has_private_exec = private_exec_regions > 0
    has_suspicious_regions = suspicious_regions > 0

    has_any_memory = (
        bool(memory_indicators)
        or has_rwx
        or has_private_exec
        or has_suspicious_regions
    )

    if not has_any_memory:
        return {
            "score": 0.0,
            "indicators": [],
            "evidence_strength": "NONE",
            "suspicious_regions": suspicious_regions,
            "writable_executable_regions": rwx_regions,
            "private_executable_regions": private_exec_regions,
        }

    # --------------------------------------------------------
    # Base memory evidence
    # --------------------------------------------------------

    unique_indicators = list(
        dict.fromkeys(
            memory_indicators
        )
    )

    score = 0.0

    for indicator in unique_indicators:
        score += MEMORY_WEIGHTS.get(
            indicator,
            0,
        )

    # --------------------------------------------------------
    # Region context
    #
    # Region counts are contextual evidence.
    # They are deliberately not multiplied directly.
    # --------------------------------------------------------

    if suspicious_regions >= 10:
        score += 5

    if suspicious_regions >= 25:
        score += 5

    # --------------------------------------------------------
    # Strong memory combination
    # --------------------------------------------------------

    if (
        has_rwx
        and has_private_exec
    ):
        score += 5

    # --------------------------------------------------------
    # Common application memory reduction
    #
    # Important:
    # This modifies the scoring contribution only.
    # Original memory evidence is preserved.
    # --------------------------------------------------------

    is_common_application = (
        normalized_name
        in COMMON_APPLICATIONS
    )

    if is_common_application:
        score *= 0.50

    # --------------------------------------------------------
    # Evidence strength
    # --------------------------------------------------------

    if score <= 0:
        strength = "NONE"

    elif score < 15:
        strength = "WEAK"

    elif score < 30:
        strength = "MODERATE"

    elif score < 50:
        strength = "STRONG"

    else:
        strength = "VERY_STRONG"

    score = min(
        round(score, 2),
        MEMORY_SCORE_CAP,
    )

    return {
        "score": score,
        "indicators": unique_indicators,
        "evidence_strength": strength,
        "suspicious_regions": suspicious_regions,
        "writable_executable_regions": rwx_regions,
        "private_executable_regions": private_exec_regions,
    }


# ============================================================
# SCORE MODE
# ============================================================

def determine_score_mode(
    *,
    has_memory: bool,
    has_behavior: bool,
    process_score: float,
    correlation_bonus: float,
    trusted_application: bool,
) -> str:
    """
    Determine why the final score was produced.
    """

    if (
        has_memory
        and has_behavior
        and correlation_bonus > 0
    ):
        return "BEHAVIOR_MEMORY_CORRELATED"

    if (
        has_memory
        and trusted_application
        and not has_behavior
        and process_score <= 0
        and correlation_bonus <= 0
    ):
        return "MEMORY_ONLY_CAPPED"

    if (
        has_memory
        and not has_behavior
        and process_score <= 0
        and correlation_bonus <= 0
    ):
        return "MEMORY_ONLY"

    if (
        has_behavior
        and not has_memory
    ):
        return "BEHAVIOR_ONLY"

    if (
        process_score > 0
        and not has_memory
        and not has_behavior
    ):
        return "PROCESS_ONLY"

    if (
        not has_memory
        and not has_behavior
        and process_score <= 0
    ):
        return "NO_EVIDENCE"

    return "COMBINED_EVIDENCE"


# ============================================================
# MAIN THREAT SCORE
# ============================================================

def calculate_threat_score(
    behavioral_indicators: List[str],
    memory_result: Dict[str, Any],
    process_indicators: List[str],
    process_name: str = "",
) -> Dict[str, Any]:
    """
    Unified context-aware PhantomTrace threat scoring.

    Important:
    - Evidence is never deleted.
    - Memory-only trusted applications are capped.
    - Behavior can still escalate trusted applications.
    - Correlated memory + behavior receives correlation scoring.
    """

    behavioral_indicators = _safe_list(
        behavioral_indicators
    )

    process_indicators = _safe_list(
        process_indicators
    )

    process_name = str(
        process_name or ""
    ).strip().lower()

    if not isinstance(
        memory_result,
        dict,
    ):
        memory_result = {}

    # --------------------------------------------------------
    # Application context
    # --------------------------------------------------------

    application_context = (
        get_application_context(
            process_name
        )
    )

    trusted_application = (
        application_context
        == "TRUSTED_COMMON_APPLICATION"
    )

    # --------------------------------------------------------
    # Behavior score
    # --------------------------------------------------------

    behavior_score = 0.0

    for indicator in set(
        behavioral_indicators
    ):
        behavior_score += BEHAVIOR_WEIGHTS.get(
            indicator,
            0,
        )

    behavior_score = min(
        behavior_score,
        BEHAVIOR_SCORE_CAP,
    )

    # --------------------------------------------------------
    # Memory score
    # --------------------------------------------------------

    memory_analysis = calculate_memory_score(
        memory_result=memory_result,
        process_name=process_name,
    )

    memory_score = float(
        memory_analysis.get(
            "score",
            0,
        )
    )

    memory_indicators = _safe_list(
        memory_analysis.get(
            "indicators",
            [],
        )
    )

    # --------------------------------------------------------
    # Process score
    # --------------------------------------------------------

    process_score = 0.0

    for indicator in set(
        process_indicators
    ):
        process_score += 5.0

    process_score = min(
        process_score,
        PROCESS_SCORE_CAP,
    )

    # --------------------------------------------------------
    # Evidence flags
    # --------------------------------------------------------

    memory_has_evidence = has_memory_evidence(
        memory_result
    )

    behavior_has_evidence = bool(
        behavioral_indicators
    )

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    correlation_bonus = 0.0

    correlation_indicators: List[str] = []

    if (
        behavior_has_evidence
        and memory_has_evidence
    ):
        correlation_bonus += (
            CORRELATION_WEIGHTS[
                "BEHAVIOR_MEMORY_CORRELATION"
            ]
        )

        correlation_indicators.append(
            "BEHAVIOR_MEMORY_CORRELATION"
        )

    if (
        "SCRIPT_INTERPRETER_ACTIVITY"
        in behavioral_indicators
        and memory_has_evidence
    ):
        correlation_bonus += (
            CORRELATION_WEIGHTS[
                "SCRIPT_MEMORY_CORRELATION"
            ]
        )

        correlation_indicators.append(
            "SCRIPT_MEMORY_CORRELATION"
        )

    if (
        "SUSPICIOUS_PARENT"
        in behavioral_indicators
        and memory_has_evidence
    ):
        correlation_bonus += (
            CORRELATION_WEIGHTS[
                "PARENT_MEMORY_CORRELATION"
            ]
        )

        correlation_indicators.append(
            "PARENT_MEMORY_CORRELATION"
        )

    correlation_bonus = min(
        correlation_bonus,
        CORRELATION_CAP,
    )

    # --------------------------------------------------------
    # Raw score
    # --------------------------------------------------------

    raw_score = (
        behavior_score
        + memory_score
        + process_score
        + correlation_bonus
    )

    raw_score = round(
        raw_score,
        2,
    )

    # --------------------------------------------------------
    # Final score
    #
    # ONLY trusted/common applications with memory-only
    # evidence are capped.
    #
    # Behavioral evidence is NOT capped.
    # Correlation is NOT capped by this rule.
    # --------------------------------------------------------

    final_score = raw_score

    memory_only_trusted = (
        trusted_application
        and memory_has_evidence
        and not behavior_has_evidence
        and process_score <= 0
        and correlation_bonus <= 0
    )

    if memory_only_trusted:
        final_score = min(
            final_score,
            MEMORY_ONLY_TRUSTED_CAP,
        )

    final_score = min(
        round(final_score, 2),
        TOTAL_SCORE_CAP,
    )

    # --------------------------------------------------------
    # Score mode
    # --------------------------------------------------------

    score_mode = determine_score_mode(
        has_memory=memory_has_evidence,
        has_behavior=behavior_has_evidence,
        process_score=process_score,
        correlation_bonus=correlation_bonus,
        trusted_application=trusted_application,
    )

    # --------------------------------------------------------
    # Context adjustment
    # --------------------------------------------------------

    if memory_only_trusted:
        memory_context_adjustment = (
            "TRUSTED_APPLICATION_MEMORY_ONLY_CAP"
        )

    elif trusted_application:
        memory_context_adjustment = (
            "TRUSTED_APPLICATION_CONTEXT"
        )

    else:
        memory_context_adjustment = (
            "STANDARD_MEMORY_WEIGHT"
        )

    context_adjusted = (
        final_score != raw_score
    )

    # --------------------------------------------------------
    # Combined indicators
    # --------------------------------------------------------

    indicators = list(
        dict.fromkeys(
            behavioral_indicators
            + memory_indicators
            + correlation_indicators
            + process_indicators
        )
    )

    # --------------------------------------------------------
    # Level
    # --------------------------------------------------------

    level = score_to_level(
        final_score
    )

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return {
        # Final decision
        "score": final_score,
        "level": level,

        # Individual scoring components
        "behavior_score": round(
            behavior_score,
            2,
        ),

        "memory_score": round(
            memory_score,
            2,
        ),

        "process_score": round(
            process_score,
            2,
        ),

        "correlation_bonus": round(
            correlation_bonus,
            2,
        ),

        # Raw score before contextual cap
        "raw_score": raw_score,

        # Evidence
        "indicators": indicators,

        "memory_evidence_strength":
            memory_analysis.get(
                "evidence_strength",
                "NONE",
            ),

        # Application context
        "application_context":
            application_context,

        "trusted_application":
            trusted_application,

        # Context adjustment
        "context_adjusted":
            context_adjusted,

        "memory_context_adjustment":
            memory_context_adjustment,

        # Pipeline metadata
        "memory_only":
            memory_only_trusted,

        "score_mode":
            score_mode,

        "correlation_indicators":
            correlation_indicators,

        # Raw memory analysis details
        "memory_suspicious_regions":
            memory_analysis.get(
                "suspicious_regions",
                0,
            ),

        "memory_writable_executable_regions":
            memory_analysis.get(
                "writable_executable_regions",
                0,
            ),

        "memory_private_executable_regions":
            memory_analysis.get(
                "private_executable_regions",
                0,
            ),

        "has_memory_evidence":
            memory_has_evidence,

        "has_behavior_evidence":
            behavior_has_evidence,
    }


# ============================================================
# THREAT SUMMARY
# ============================================================

def summarize_threats(
    results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Summarize complete scan results.

    Alert records remain structured.
    """

    summary = {
        "total_processes": len(results),
        "normal": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
        "threat_alerts": [],
        "highest_score": 0.0,
    }

    for result in results:

        threat = result.get(
            "threat",
            result,
        )

        if not isinstance(
            threat,
            dict,
        ):
            continue

        score = _safe_float(
            threat.get(
                "score",
                result.get(
                    "score",
                    0,
                ),
            )
        )

        level = str(
            threat.get(
                "level",
                result.get(
                    "level",
                    "NORMAL",
                ),
            )
        ).upper()

        if level == "NORMAL":
            summary["normal"] += 1

        elif level == "LOW":
            summary["low"] += 1

        elif level == "MEDIUM":
            summary["medium"] += 1

        elif level == "HIGH":
            summary["high"] += 1

        elif level == "CRITICAL":
            summary["critical"] += 1

        summary["highest_score"] = max(
            summary["highest_score"],
            score,
        )

        # LOW and above are alerts.
        if level != "NORMAL":

            summary[
                "threat_alerts"
            ].append(
                {
                    "pid":
                        result.get(
                            "pid"
                        ),

                    "name":
                        result.get(
                            "name",
                            "Unknown",
                        ),

                    "score":
                        score,

                    "level":
                        level,

                    "application_context":
                        threat.get(
                            "application_context",
                            result.get(
                                "application_context",
                                "STANDARD_PROCESS",
                            ),
                        ),

                    "score_mode":
                        threat.get(
                            "score_mode",
                            result.get(
                                "score_mode",
                                "UNKNOWN",
                            ),
                        ),

                    "behavior_score":
                        threat.get(
                            "behavior_score",
                            result.get(
                                "behavior_score",
                                0,
                            ),
                        ),

                    "memory_score":
                        threat.get(
                            "memory_score",
                            result.get(
                                "memory_score",
                                0,
                            ),
                        ),

                    "process_score":
                        threat.get(
                            "process_score",
                            result.get(
                                "process_score",
                                0,
                            ),
                        ),

                    "correlation_bonus":
                        threat.get(
                            "correlation_bonus",
                            result.get(
                                "correlation_bonus",
                                0,
                            ),
                        ),

                    "memory_evidence_strength":
                        threat.get(
                            "memory_evidence_strength",
                            result.get(
                                "memory_evidence_strength",
                                "NONE",
                            ),
                        ),

                    "indicators":
                        threat.get(
                            "indicators",
                            result.get(
                                "indicators",
                                [],
                            ),
                        ),
                }
            )

    return summary
