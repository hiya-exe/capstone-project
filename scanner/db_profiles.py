"""Database-type profiling: environment tier + engine-specific guidance.

This is a second profiling axis on top of the industry business profiles
(scanner/profiles.py). Where an industry profile answers "how strict should
this be for our regulatory context", this module answers two narrower
questions for RDS findings specifically:

1. Does this database actually hold production data, or is it a
   disposable dev/staging instance? (severity should scale accordingly)
2. What does fixing this finding actually cost/require on this engine?
   (the business benefit/cost framing: open-source engines get
   encryption "for free"; commercial engines often gate it behind
   licensing tiers)
"""

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]

ENVIRONMENT_SEVERITY_SHIFT = {
    "production": 0,
    "staging": -1,
    "development": -2,
    "unknown": 0,
}

ENGINE_NOTES = {
    "aurora-mysql": "Aurora provides built-in continuous backup and IAM database authentication, so remediation is low-cost and doesn't require new licensing.",
    "aurora-postgresql": "Aurora provides built-in continuous backup and IAM database authentication, so remediation is low-cost and doesn't require new licensing.",
    "mysql": "Encryption and access controls are free, built-in engine features on MySQL — there is no licensing barrier to remediation.",
    "postgres": "Encryption and access controls are free, built-in engine features on PostgreSQL — there is no licensing barrier to remediation.",
    "mariadb": "Encryption and access controls are free, built-in engine features on MariaDB — there is no licensing barrier to remediation.",
    "sqlserver-ee": "Transparent Data Encryption (TDE) is available on this Enterprise edition, but upgrading config still has operational cost to plan for.",
    "sqlserver-se": "Transparent Data Encryption (TDE) requires Standard edition or higher — confirm licensing tier before committing to a remediation date.",
    "sqlserver-web": "Web edition does not support Transparent Data Encryption (TDE) — an edition upgrade (added licensing cost) is required to remediate encryption findings.",
    "sqlserver-ex": "Express edition does not support Transparent Data Encryption (TDE) — an edition upgrade (added licensing cost) is required to remediate encryption findings.",
    "oracle-ee": "Oracle Advanced Security (encryption) is a licensed add-on — factor that license cost into the remediation plan.",
    "oracle-se2": "Oracle Advanced Security (encryption) is a licensed add-on — factor that license cost into the remediation plan.",
}

DEFAULT_ENGINE_NOTE = "No engine-specific licensing constraints identified for this engine."


def adjust_severity(severity, environment):
    if severity not in SEVERITY_ORDER:
        return severity
    shift = ENVIRONMENT_SEVERITY_SHIFT.get(environment, 0)
    idx = SEVERITY_ORDER.index(severity)
    idx = max(0, min(len(SEVERITY_ORDER) - 1, idx + shift))
    return SEVERITY_ORDER[idx]


def get_engine_note(engine):
    return ENGINE_NOTES.get(engine, DEFAULT_ENGINE_NOTE)


def infer_environment(db_identifier, tags=None):
    tags = tags or {}
    env = tags.get("Environment") or tags.get("environment") or tags.get("Env")
    if env:
        return env.strip().lower()
    db_id = (db_identifier or "").lower()
    if "prod" in db_id:
        return "production"
    if "stag" in db_id:
        return "staging"
    if "dev" in db_id or "test" in db_id:
        return "development"
    return "unknown"
