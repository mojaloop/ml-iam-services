import { Elector, LeaseRecord, LeaseSpec, LeaseStore, Timing } from '../../src/controller/leader';

/** One Lease as the API server keeps it: a write over a stale version is refused, and every landed write is watched. */
class MemoryLease implements LeaseStore {
  record: LeaseRecord = { version: '1' };
  failing = false;
  private readonly watchers = new Set<(record: LeaseRecord) => void>();

  async read(): Promise<LeaseRecord> {
    return this.record;
  }

  async write(spec: LeaseSpec, version: string): Promise<LeaseRecord | undefined> {
    if (this.failing) throw new Error('connect ECONNREFUSED');
    if (version !== this.record.version) return undefined;
    this.record = { ...spec, version: String(Number(this.record.version) + 1) };
    const landed = this.record;
    for (const watcher of this.watchers) queueMicrotask(() => watcher(landed));
    return landed;
  }

  async watch(onRecord: (record: LeaseRecord) => void): Promise<{ close: () => void }> {
    this.watchers.add(onRecord);
    return { close: () => this.watchers.delete(onRecord) };
  }
}

/** One replica's way to the Lease, which a partition can cut. */
const reachable = (store: MemoryLease) => {
  const view = {
    cut: false,
    read: () => (view.cut ? Promise.reject(new Error('unreachable')) : store.read()),
    write: (spec: LeaseSpec, version: string) => (view.cut ? Promise.reject(new Error('unreachable')) : store.write(spec, version)),
    watch: (onRecord: (record: LeaseRecord) => void) => store.watch((record) => view.cut || onRecord(record)),
  };
  return view;
};

const TIMING: Timing = { durationSeconds: 10, renewDeadlineMs: 8000, renewEveryMs: 2000 };

const replica = (store: LeaseStore, identity: string, timing: Timing = TIMING) => {
  const seen = { leading: 0, lost: [] as string[] };
  const elector = new Elector({
    store,
    identity,
    address: `http://${identity}:3003`,
    timing,
    onLeading: () => {
      seen.leading += 1;
    },
    onLost: (reason) => seen.lost.push(reason),
    clock: () => Date.now(),
  });
  return { elector, seen };
};

describe('leader election through a Lease', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('takes a lease nobody holds, and names itself and its address on it', async () => {
    const store = new MemoryLease();
    const a = replica(store, 'a');
    await a.elector.start();
    expect(a.elector.leader).toEqual({ self: true });
    expect(a.seen.leading).toBe(1);
    expect(store.record).toMatchObject({ holder: 'a@http://a:3003', durationSeconds: 10, transitions: 0 });
  });

  it('lets exactly one of two replicas starting together lead, and tells the other where it is', async () => {
    const store = new MemoryLease();
    const a = replica(store, 'a');
    const b = replica(store, 'b');
    await Promise.all([a.elector.start(), b.elector.start()]);
    await vi.advanceTimersByTimeAsync(0);
    const leading = [a, b].filter((r) => r.elector.leader.self);
    expect(leading).toHaveLength(1);
    const standby = [a, b].find((r) => !r.elector.leader.self)!;
    expect(standby.elector.leader).toEqual({ self: false, address: leading[0] === a ? 'http://a:3003' : 'http://b:3003' });
  });

  it('keeps the lease by renewing it, so a standby never takes it from a live leader', async () => {
    const store = new MemoryLease();
    const a = replica(store, 'a');
    await a.elector.start();
    const b = replica(store, 'b');
    await b.elector.start();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(a.elector.leader).toEqual({ self: true });
    expect(b.seen.leading).toBe(0);
    expect(a.seen.lost).toEqual([]);
  });

  it('hands over the moment the leader releases, without waiting out the lease', async () => {
    const store = new MemoryLease();
    const a = replica(store, 'a');
    await a.elector.start();
    const b = replica(store, 'b');
    await b.elector.start();
    await a.elector.release();
    await vi.advanceTimersByTimeAsync(0);
    expect(b.elector.leader).toEqual({ self: true });
    expect(store.record).toMatchObject({ holder: 'b@http://b:3003', transitions: 0 });
  });

  it('lets a leader cut off from the Lease stop at its deadline, and the standby take over only once the lease lapses', async () => {
    const store = new MemoryLease();
    const toA = reachable(store);
    const a = replica(toA, 'a');
    await a.elector.start();
    const b = replica(store, 'b');
    await b.elector.start();
    toA.cut = true;

    await vi.advanceTimersByTimeAsync(8_000);
    expect(a.seen.lost).toEqual(['no renewal landed for 8000 ms']);
    expect(b.elector.leader).toEqual({ self: false, address: 'http://a:3003' });
    await vi.advanceTimersByTimeAsync(1_999);
    expect(b.elector.leader.self).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(b.elector.leader).toEqual({ self: true });
    expect(store.record).toMatchObject({ holder: 'b@http://b:3003', transitions: 1 });
  });

  it('stops leading at the renew deadline when no renewal lands, before anyone may take the lease', async () => {
    const store = new MemoryLease();
    const a = replica(store, 'a');
    await a.elector.start();
    store.failing = true;
    await vi.advanceTimersByTimeAsync(7_999);
    expect(a.elector.leader).toEqual({ self: true });
    await vi.advanceTimersByTimeAsync(1);
    expect(a.seen.lost).toEqual(['no renewal landed for 8000 ms']);
    expect(a.elector.leader.self).toBe(false);
  });

  it('stops leading when the lease names another holder', async () => {
    const store = new MemoryLease();
    const a = replica(store, 'a');
    await a.elector.start();
    await store.write({ ...store.record, holder: 'intruder@http://x:3003' }, store.record.version);
    await vi.advanceTimersByTimeAsync(0);
    expect(a.seen.lost).toEqual(['intruder@http://x:3003 holds the lease']);
  });

  it('resumes at once a lease held by the same replica, as a restarted container finds it', async () => {
    const store = new MemoryLease();
    store.record = { holder: 'a@http://a:3003', durationSeconds: 10, renewTime: new Date().toISOString(), transitions: 3, version: '7' };
    const a = replica(store, 'a');
    await a.elector.start();
    expect(a.elector.leader).toEqual({ self: true });
    expect(store.record.transitions).toBe(3);
  });

  it('answers no address while no replica holds a live lease', async () => {
    const store = new MemoryLease();
    store.record = { holder: '', version: '2' };
    store.failing = true;
    const a = replica(store, 'a');
    await a.elector.start();
    expect(a.elector.leader).toEqual({ self: false });
  });

  it.each([
    [{ durationSeconds: 10, renewDeadlineMs: 10_000, renewEveryMs: 2000 }],
    [{ durationSeconds: 10, renewDeadlineMs: 8000, renewEveryMs: 8000 }],
  ])('refuses timing that could let two replicas write at once: %j', (timing) => {
    expect(() => replica(new MemoryLease(), 'a', timing)).toThrow(/lease timing/);
  });
});
