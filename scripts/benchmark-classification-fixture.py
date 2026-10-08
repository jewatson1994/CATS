"""Give benchmark services a realistic classification mix (disposable databases only).

The navigation harness seeds findings that are all a day old, with no
exceptions, so nothing is overdue, excepted or about to expire and the
classification paths are barely exercised. This deterministic fixture, for
the named services:

* ages episodes: about 35% of active findings become 100-400 days old
  (overdue under every default due rule), 25% 31-99 days old (overdue for
  Critical/High only), the rest keep their age;
* adds exceptions to about 3% of active findings: 2% current, 0.5% expired,
  0.3% starting in the future, 0.2% revoked;
* invalidates the services' posture rows (and classification state, when the
  table exists), as a real write would.

    python scripts/benchmark-classification-fixture.py --database-url URL --service perf-9999 --service perf-0001

Never point it at a real CATS database: it rewrites finding ages.
"""
import argparse
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, inspect, text


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--service", action="append", required=True)
    args = parser.parse_args()
    engine = create_engine(args.database_url)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with engine.begin() as connection:
        tables = set(inspect(connection).get_table_names())
        for key in args.service:
            service_id = connection.execute(text("select id from services where service_key = :key"), {"key": key}).scalar()
            if service_id is None:
                raise SystemExit(f"unknown service {key}")
            # Deterministic buckets from the finding id.
            connection.execute(text("""
                update findings set episode_started = :now - make_interval(days => (100 + (id::bigint * 7919) % 300)::int)
                where service_id = :sid and active and (id::bigint * 2654435761) % 100 < 35"""), {"now": now, "sid": service_id})
            connection.execute(text("""
                update findings set episode_started = :now - make_interval(days => (31 + (id::bigint * 104729) % 69)::int)
                where service_id = :sid and active and (id::bigint * 2654435761) % 100 between 35 and 59"""), {"now": now, "sid": service_id})
            connection.execute(text("""
                delete from exceptions where finding_id in (select id from findings where service_id = :sid)
                and justification = 'benchmark fixture'"""), {"sid": service_id})
            for low, high, starts, expires, revoked in (
                    (0, 199, -30, 60, False),      # current
                    (200, 249, -120, -10, False),  # expired
                    (250, 279, 20, 120, False),    # starts in the future
                    (280, 299, -30, 60, True)):    # revoked
                connection.execute(text("""
                    insert into exceptions (finding_id, justification, approved_by, ticket, starts_at, expires_at, revoked_at, created_at)
                    select id, 'benchmark fixture', 'benchmark', null, :now + make_interval(days => :starts),
                           :now + make_interval(days => :expires), case when :revoked then :now else null end, :now
                    from findings where service_id = :sid and active and (id::bigint * 40503) % 10000 between :low and :high"""),
                    {"now": now, "sid": service_id, "starts": starts, "expires": expires, "revoked": revoked,
                     "low": low, "high": high})
            connection.execute(text("update service_posture set data_generation = data_generation + 1 where service_id = :sid"),
                               {"sid": service_id})
            if "finding_classification_changes" in tables:
                connection.execute(text("insert into finding_classification_changes (service_id, finding_id) values (:sid, null)"),
                                   {"sid": service_id})
            counts = connection.execute(text("""
                select count(*) filter (where active) as active,
                       count(*) filter (where active and episode_started < :now - interval '90 days') as older_90,
                       (select count(*) from exceptions e join findings f on f.id = e.finding_id
                        where f.service_id = :sid and e.justification = 'benchmark fixture') as exceptions
                from findings where service_id = :sid"""), {"now": now, "sid": service_id}).one()
            print(f"{key}: active={counts.active} older_than_90_days={counts.older_90} exceptions={counts.exceptions}")


if __name__ == "__main__":
    main()
