import { performance } from 'node:perf_hooks';

import { Logged } from '../logged';

/**
 * Leadership among the controller's replicas, held as one Lease. The holder
 * renews it; a replica that sees it released takes it at once, and one that
 * sees it go unrenewed for its whole duration takes it then. Expiry is counted
 * from when this process saw the lease change, on its own clock, never from
 * the times the holder wrote, so the replicas' clocks need not agree.
 */

export interface LeaseRecord {
  /** `<identity>@<address>`: who holds the lease, and where it takes the writes only it makes. */
  holder?: string;
  durationSeconds?: number;
  acquireTime?: string;
  renewTime?: string;
  transitions?: number;
  /** The version this record was read at. */
  version: string;
}

export type LeaseSpec = Omit<LeaseRecord, 'version'>;

export interface LeaseStore {
  read(): Promise<LeaseRecord>;
  /** Writes over the version named, or answers nothing when another write landed first. */
  write(spec: LeaseSpec, version: string): Promise<LeaseRecord | undefined>;
  watch(onRecord: (record: LeaseRecord) => void): Promise<{ close: () => void }>;
}

export interface Timing {
  /** How long the lease holds unrenewed, in whole seconds as a Lease carries it. */
  durationSeconds: number;
  /** How long the holder goes on writing without a renewal landing: less than the duration. */
  renewDeadlineMs: number;
  /** How often the holder renews: less than the deadline, so a failed renewal is retried before it. */
  renewEveryMs: number;
}

/** Where the writes go: this replica, another one, or nowhere while no replica leads. */
export type Leader = { self: true } | { self: false; address?: string };

export const addressOf = (holder: string | undefined): string | undefined => {
  const at = holder?.indexOf('@') ?? -1;
  return at > 0 ? holder!.slice(at + 1) : undefined;
};

export interface ElectorOptions {
  store: LeaseStore;
  identity: string;
  address: string;
  timing: Timing;
  /** This replica now leads: what only the leader does may start. */
  onLeading: () => void;
  /** This replica no longer leads, and must stop writing at once. */
  onLost: (reason: string) => void;
  clock?: () => number;
}

export class Elector {
  private readonly holder: string;
  private readonly durationMs: number;
  private readonly clock: () => number;
  private record?: LeaseRecord;
  private observedAt = 0;
  private leading = false;
  private stopped = false;
  private attempting = false;
  private expiry?: NodeJS.Timeout;
  private renewal?: NodeJS.Timeout;
  private deadline?: NodeJS.Timeout;
  private watcher?: { close: () => void };

  constructor(private readonly options: ElectorOptions) {
    const { durationSeconds, renewDeadlineMs, renewEveryMs } = options.timing;
    this.durationMs = durationSeconds * 1000;
    if (!(renewEveryMs < renewDeadlineMs && renewDeadlineMs < this.durationMs)) {
      throw new Error(`lease timing must renew within its deadline and stop before it expires: ${JSON.stringify(options.timing)}`);
    }
    if (options.identity.includes('@')) throw new Error(`a lease identity holds no @: ${options.identity}`);
    this.holder = `${options.identity}@${options.address}`;
    this.clock = options.clock ?? (() => performance.now());
  }

  get leader(): Leader {
    if (this.leading) return { self: true };
    const holder = this.record?.holder;
    if (holder === undefined || holder === '' || this.expired()) return { self: false };
    return { self: false, address: addressOf(holder) };
  }

  async start(): Promise<void> {
    this.watcher = await this.options.store.watch((record) => this.observe(record));
    this.observe(await this.options.store.read());
    await this.attempt();
  }

  /** Gives the lease up, so another replica takes it on the change instead of waiting out its duration. */
  async release(): Promise<void> {
    this.stopped = true;
    this.watcher?.close();
    this.clear();
    if (!this.leading || this.record === undefined) return;
    this.leading = false;
    await this.options.store.write({ ...spec(this.record), holder: '', renewTime: new Date().toISOString() }, this.record.version);
  }

  private expired(): boolean {
    return this.clock() - this.observedAt >= this.durationMs;
  }

  private observe(record: LeaseRecord): void {
    const before = this.record;
    if (before !== undefined && before.version === record.version) return;
    this.record = record;
    if (before === undefined || before.holder !== record.holder || before.renewTime !== record.renewTime) {
      this.observedAt = this.clock();
    }
    if (this.stopped) return;
    if (this.leading) {
      if (record.holder !== this.holder) this.lose(`${record.holder || 'nobody'} holds the lease`);
      return;
    }
    if (!record.holder) {
      void this.attempt();
      return;
    }
    if (record.holder === this.holder) {
      void this.attempt();
      return;
    }
    clearTimeout(this.expiry);
    this.expiry = setTimeout(() => void this.attempt(), Math.max(0, this.observedAt + this.durationMs - this.clock()));
  }

  /** Takes the lease when nobody holds it, its holder let it lapse, or the holder is this replica's own earlier process. */
  private async attempt(): Promise<void> {
    if (this.stopped || this.leading || this.attempting || this.record === undefined) return;
    const current = this.record;
    const free = !current.holder || current.holder === this.holder || this.expired();
    if (!free) return;
    this.attempting = true;
    try {
      const now = new Date().toISOString();
      const taken = current.holder !== this.holder;
      const written = await this.options.store.write(
        {
          holder: this.holder,
          durationSeconds: this.options.timing.durationSeconds,
          acquireTime: taken ? now : (current.acquireTime ?? now),
          renewTime: now,
          transitions: (current.transitions ?? 0) + (taken && current.holder ? 1 : 0),
        },
        current.version,
      );
      if (written === undefined) {
        this.observe(await this.options.store.read());
        return;
      }
      this.record = written;
      this.observedAt = this.clock();
      this.lead();
    } catch (error) {
      console.error(JSON.stringify({ event: Logged.leaseAcquireFailed, error: String(error) }));
    } finally {
      this.attempting = false;
    }
  }

  private lead(): void {
    if (this.stopped) return;
    this.leading = true;
    clearTimeout(this.expiry);
    this.renewed();
    console.log(JSON.stringify({ event: Logged.leading, holder: this.holder }));
    this.options.onLeading();
  }

  /** A renewal landed: the deadline counts from now, and the next renewal is due. */
  private renewed(): void {
    clearTimeout(this.deadline);
    this.deadline = setTimeout(
      () => this.lose(`no renewal landed for ${this.options.timing.renewDeadlineMs} ms`),
      this.options.timing.renewDeadlineMs,
    );
    this.scheduleRenewal();
  }

  private scheduleRenewal(): void {
    clearTimeout(this.renewal);
    this.renewal = setTimeout(() => void this.renew(), this.options.timing.renewEveryMs);
  }

  private async renew(): Promise<void> {
    if (!this.leading || this.record === undefined) return;
    try {
      const written = await this.options.store.write({ ...spec(this.record), renewTime: new Date().toISOString() }, this.record.version);
      if (!this.leading) return;
      if (written === undefined) {
        this.observe(await this.options.store.read());
        if (this.leading) this.scheduleRenewal();
        return;
      }
      this.record = written;
      this.observedAt = this.clock();
      this.renewed();
    } catch (error) {
      console.error(JSON.stringify({ event: Logged.leaseRenewFailed, error: String(error) }));
      if (this.leading) this.scheduleRenewal();
    }
  }

  private lose(reason: string): void {
    if (!this.leading) return;
    this.leading = false;
    this.clear();
    console.error(JSON.stringify({ event: Logged.leadershipLost, holder: this.holder, reason }));
    this.options.onLost(reason);
  }

  private clear(): void {
    clearTimeout(this.expiry);
    clearTimeout(this.renewal);
    clearTimeout(this.deadline);
  }
}

const spec = (record: LeaseRecord): LeaseSpec => {
  const rest: LeaseSpec & { version?: string } = { ...record };
  delete rest.version;
  return rest;
};
