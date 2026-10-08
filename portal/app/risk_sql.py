"""Database-native Python-compatible JSON risk value precedence and coercion."""
from sqlalchemy import Boolean, Float
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.functions import FunctionElement


class EvidencePresent(FunctionElement):
    type = Boolean()
    inherit_cache = False

    def __init__(self, evidence, key):
        if key not in {"kev", "known_exploited", "epss", "epss_score"}:
            raise ValueError("Unsupported risk key")
        self.key = key
        super().__init__(evidence)


@compiles(EvidencePresent, "sqlite")
def _present_sqlite(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    return f"(json_type({column}, '$.{element.key}') IS NOT NULL)"


@compiles(EvidencePresent, "postgresql")
def _present_postgres(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    return f"(CAST({column} AS jsonb) ? '{element.key}')"


class EvidenceTruth(FunctionElement):
    type = Boolean()
    inherit_cache = False


class EvidenceScore(FunctionElement):
    type = Float()
    inherit_cache = False


def _selected(column, primary, secondary, dialect):
    if dialect == "sqlite":
        return f"CASE WHEN json_type({column}, '$.{primary}') IS NOT NULL THEN '$.{primary}' ELSE '$.{secondary}' END"
    return f"CASE WHEN CAST({column} AS jsonb) ? '{primary}' THEN '{primary}' ELSE '{secondary}' END"


@compiles(EvidenceTruth, "sqlite")
def _truth_sqlite(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    path = _selected(column, "kev", "known_exploited", "sqlite")
    value, kind = f"json_extract({column}, {path})", f"json_type({column}, {path})"
    return (f"(CASE {kind} WHEN 'null' THEN 0 WHEN 'false' THEN 0 WHEN 'true' THEN 1 "
            f"WHEN 'text' THEN {value} <> '' WHEN 'array' THEN json_array_length({value}) > 0 "
            f"WHEN 'object' THEN {value} <> '{{}}' ELSE COALESCE({value} <> 0, 0) END)" )


def _truth_postgres_value(value):
    """Python truthiness of one jsonb value (Services' KEV normalization)."""
    return (f"(CASE jsonb_typeof({value}) WHEN 'null' THEN false "
            f"WHEN 'boolean' THEN {value} = 'true'::jsonb WHEN 'string' THEN {value} <> '\"\"'::jsonb "
            f"WHEN 'array' THEN jsonb_array_length({value}) > 0 WHEN 'object' THEN {value} <> '{{}}'::jsonb "
            f"WHEN 'number' THEN CAST({value} AS numeric) <> 0 ELSE false END)")


@compiles(EvidenceTruth, "postgresql")
def _truth_postgres(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    key = _selected(column, "kev", "known_exploited", "postgresql")
    return _truth_postgres_value(f"(CAST({column} AS jsonb) -> ({key}))")


@compiles(EvidenceScore, "sqlite")
def _score_sqlite(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    path = _selected(column, "epss", "epss_score", "sqlite")
    # A short SQL finite-state parser avoids SQLite's permissive CAST('1junk')
    # and needs no custom Python SQL function. Underscores require digit neighbors.
    return f"""(WITH RECURSIVE
      input(s, kind, raw) AS (
        SELECT lower(trim(CAST(json_extract({column}, {path}) AS TEXT), char(9)||char(10)||char(11)||char(12)||char(13)||' ')),
               json_type({column}, {path}), json_extract({column}, {path})),
      parse(i, state) AS (
        SELECT 1, 'start'
        UNION ALL
        SELECT i+1, CASE
          WHEN substr(s,i,1) GLOB '[0-9]' THEN CASE
            WHEN state IN ('start','sign','int','int_us') THEN 'int'
            WHEN state IN ('dot','dot_int','frac','frac_us') THEN 'frac'
            WHEN state IN ('exp','exp_sign','exp_int','exp_us') THEN 'exp_int' ELSE 'bad' END
          WHEN substr(s,i,1) IN ('+','-') AND state='start' THEN 'sign'
          WHEN substr(s,i,1) IN ('+','-') AND state='exp' THEN 'exp_sign'
          WHEN substr(s,i,1)='.' AND state IN ('start','sign') THEN 'dot'
          WHEN substr(s,i,1)='.' AND state='int' THEN 'dot_int'
          WHEN substr(s,i,1)='e' AND state IN ('int','dot_int','frac') THEN 'exp'
          WHEN substr(s,i,1)='_' AND state='int' THEN 'int_us'
          WHEN substr(s,i,1)='_' AND state='frac' THEN 'frac_us'
          WHEN substr(s,i,1)='_' AND state='exp_int' THEN 'exp_us'
          ELSE 'bad' END
        FROM parse, input WHERE i <= length(s) AND state <> 'bad')
      SELECT CASE
        WHEN kind IN ('integer','real','true','false') THEN CAST(raw AS REAL)
        WHEN kind <> 'text' OR kind IS NULL THEN 0.0
        WHEN s IN ('nan','+nan','-nan') THEN NULL
        WHEN s IN ('inf','+inf','infinity','+infinity') THEN 1e999
        WHEN s IN ('-inf','-infinity') THEN -1e999
        WHEN EXISTS(SELECT 1 FROM parse WHERE i=length(s)+1 AND state IN ('int','dot_int','frac','exp_int'))
          THEN CAST(replace(s,'_','') AS REAL)
        ELSE 0.0 END FROM input)"""


@compiles(EvidenceScore, "postgresql")
def _score_postgres(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    key = _selected(column, "epss", "epss_score", "postgresql")
    return _score_postgres_value(f"(CAST({column} AS jsonb) -> ({key}))")


def _score_postgres_value(value):
    """Python ``float()`` of one jsonb value (Services' EPSS normalization)."""
    # Numeric first avoids double-precision overflow/underflow exceptions. Huge
    # exponents saturate like Python float; numeric never receives that exponent.
    pattern = r"^[+-]?([0-9](_?[0-9])*(\.([0-9](_?[0-9])*)?)?|\.[0-9](_?[0-9])*)(e[+-]?[0-9](_?[0-9])*)?$"
    return f"""(SELECT CASE
      WHEN kind='boolean' THEN CASE WHEN raw='true' THEN 1.0 ELSE 0.0 END
      WHEN kind NOT IN ('string','number') OR kind IS NULL THEN 0.0
      WHEN s IN ('nan','+nan','-nan') THEN NULL
      WHEN s IN ('inf','+inf','infinity','+infinity') THEN 'Infinity'::double precision
      WHEN s IN ('-inf','-infinity') THEN '-Infinity'::double precision
      WHEN s ~ '{pattern}' THEN (
        SELECT CASE WHEN abs(n) > 1.7976931348623157e308 THEN
          CASE WHEN n < 0 THEN '-Infinity'::double precision ELSE 'Infinity'::double precision END
          WHEN abs(n) < 4.9406564584124654e-324 THEN 0.0 ELSE CAST(n AS double precision) END
        FROM (SELECT CASE
          WHEN length(ltrim(regexp_replace(split_part(clean,'e',2),'^[+-]','',''), '0')) > 3 THEN
            CASE WHEN split_part(clean,'e',2) LIKE '-%%' THEN 0::numeric
                 WHEN clean LIKE '-%%' THEN -1e1000::numeric ELSE 1e1000::numeric END
          ELSE CAST(clean AS numeric) END AS n
          FROM (SELECT replace(s,'_','') AS clean) normalized) numeric_value)
      ELSE 0.0 END FROM (
        SELECT jsonb_typeof({value}) AS kind, {value} #>> '{{}}' AS raw,
          lower(btrim({value} #>> '{{}}', E' \\t\\n\\r\\f\\v')) AS s) input)"""


class EvidenceKeyBoolean(FunctionElement):
    """``evidence[key]`` as a boolean, never raising on PostgreSQL.

    The Cybersecurity read model historically used ``evidence[key].as_boolean()``,
    which on PostgreSQL is ``CAST(evidence ->> key AS boolean)``: a missing or
    JSON-null key is NULL, a valid boolean literal ('true', 'yes', '1', ...) is
    its value, and any other text (``""``, ``[1]``, ``2``, ...) raised an error
    and failed the whole page. Here every value that cast before keeps exactly
    that result, and only the values that raised use Services' normalization
    (Python truthiness of the JSON value). SQLite compiles exactly as before.
    """
    type = Boolean()
    inherit_cache = False

    def __init__(self, evidence, key):
        if key not in {"kev", "known_exploited"}:
            raise ValueError("Unsupported risk key")
        self.key = key
        super().__init__(evidence)


class EvidenceKeyFloat(FunctionElement):
    """``evidence[key]`` as a float, never raising on PostgreSQL.

    As ``EvidenceKeyBoolean`` for ``as_float()``: valid double precision text
    keeps its cast; text that raised (``"junk"``, ``""``, booleans, arrays,
    out-of-range numbers) uses Services' EPSS parsing instead.
    """
    type = Float()
    inherit_cache = False

    def __init__(self, evidence, key):
        if key not in {"epss", "epss_score"}:
            raise ValueError("Unsupported risk key")
        self.key = key
        super().__init__(evidence)


@compiles(EvidenceKeyBoolean)
def _key_boolean_default(element, compiler, **kw):
    return compiler.process(list(element.clauses)[0][element.key].as_boolean(), **kw)


@compiles(EvidenceKeyFloat)
def _key_float_default(element, compiler, **kw):
    return compiler.process(list(element.clauses)[0][element.key].as_float(), **kw)


_PG_SPACE = r"E' \t\n\r\v\f'"
_PG_BOOLEAN_LITERALS = ("t", "tr", "tru", "true", "y", "ye", "yes", "on", "1",
                        "f", "fa", "fal", "fals", "false", "n", "no", "of", "off", "0")
_PG_FLOAT_PATTERN = r"^[+-]?(([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+)?|nan|inf|infinity)$"


def _valid_input(compiler, text, type_name):
    """Would ``CAST(text AS type)`` succeed? Exact on PostgreSQL 16+
    (``pg_input_is_valid``, the shipped database). Older servers use an
    explicit literal test: exact for booleans; for floats, decimal, NaN and
    infinity text in range (hexadecimal text, which the C parser also
    accepts, then gets Services' value instead of its cast)."""
    version = getattr(compiler.dialect, "server_version_info", None) or (16,)
    if version >= (16,):
        return f"pg_input_is_valid({text}, '{type_name}')"
    trimmed = f"lower(btrim({text}, {_PG_SPACE}))"
    if type_name == "boolean":
        literals = ", ".join(f"'{value}'" for value in _PG_BOOLEAN_LITERALS)
        return f"({trimmed} IN ({literals}))"
    return (f"({trimmed} ~ '{_PG_FLOAT_PATTERN}' AND ({trimmed} IN ('nan', 'inf', 'infinity', '+inf', '-inf', "
            f"'+infinity', '-infinity') OR CAST({trimmed} AS numeric) = 0 OR abs(CAST({trimmed} AS numeric)) "
            f"BETWEEN 2.2250738585072014e-308 AND 1.7976931348623157e308))")


@compiles(EvidenceKeyBoolean, "postgresql")
def _key_boolean_postgres(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    text = f"(CAST({column} AS json) ->> '{element.key}')"
    value = f"(CAST({column} AS jsonb) -> '{element.key}')"
    guarded = (f"(CASE WHEN {text} IS NULL THEN NULL WHEN {_valid_input(compiler, text, 'boolean')} "
               f"THEN CAST({text} AS boolean) ELSE {_truth_postgres_value(value)} END)")
    # JSON booleans (the common case) read as 'true'/'false': a simple CASE
    # extracts the text once and returns the cast's own result directly.
    return f"(CASE {text} WHEN 'true' THEN true WHEN 'false' THEN false ELSE {guarded} END)"


@compiles(EvidenceKeyFloat, "postgresql")
def _key_float_postgres(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    text = f"(CAST({column} AS json) ->> '{element.key}')"
    value = f"(CAST({column} AS jsonb) -> '{element.key}')"
    return (f"(CASE WHEN {text} IS NULL THEN NULL WHEN {_valid_input(compiler, text, 'double precision')} "
            f"THEN CAST({text} AS double precision) ELSE {_score_postgres_value(value)} END)")


key_present = EvidencePresent
evidence_truth = EvidenceTruth
evidence_score = EvidenceScore
evidence_key_boolean = EvidenceKeyBoolean
evidence_key_float = EvidenceKeyFloat
