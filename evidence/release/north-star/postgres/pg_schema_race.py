"""Reproduce: N processes construct PostgresReplayStore at the same instant against an EMPTY database."""
import multiprocessing as mp, sys, time
def worker(dsn, barrier, q):
    from actenon.replay import PostgresReplayStore
    barrier.wait()
    try:
        PostgresReplayStore(dsn); q.put("ok")
    except Exception as e:
        q.put(f"{type(e).__name__}: {str(e).splitlines()[0]}")
if __name__ == "__main__":
    base, rounds, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    import psycopg
    failures = 0
    for r in range(rounds):
        db = f"race_{r}"
        with psycopg.connect(base + " dbname=postgres", autocommit=True) as c:
            c.execute(f"DROP DATABASE IF EXISTS {db}"); c.execute(f"CREATE DATABASE {db}")
        barrier, q = mp.Barrier(n), mp.Queue()
        ps = [mp.Process(target=worker, args=(base + f" dbname={db}", barrier, q)) for _ in range(n)]
        [p.start() for p in ps]; [p.join() for p in ps]
        res = [q.get() for _ in range(n)]
        bad = [x for x in res if x != "ok"]; failures += len(bad)
        if bad: print(f"round {r}: {len(bad)}/{n} constructors failed: {sorted(set(bad))}")
    print(f"TOTAL constructor failures: {failures} over {rounds} rounds x {n} processes")
