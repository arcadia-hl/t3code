// @effect-diagnostics nodeBuiltinImport:off -- Renderer callbacks use opaque lease IDs in this synchronous ownership registry.
import * as NodeCrypto from "node:crypto";

type Gateway = { close(): Promise<void> };

// A pending native acquisition can finish after its renderer or app scope dies.
// Keep the owner tombstone until shutdown so that late acquisitions close too.
export class GatewayOwners {
  private readonly owners = new Map<number, { alive: boolean; unsubscribe: () => void }>();
  private readonly leases = new Map<string, { ownerId: number; gateway: Gateway }>();
  private pending = 0;
  private stopped = false;

  observe(ownerId: number, subscribe: (destroy: () => void) => () => void): void {
    if (this.stopped) throw new Error("Gateway scope closed.");
    if (this.owners.has(ownerId)) return;
    const owner = { alive: true, unsubscribe: () => {} };
    this.owners.set(ownerId, owner);
    owner.unsubscribe = subscribe(() => {
      void this.closeOwner(ownerId).catch(() => {});
    });
    if (!owner.alive) owner.unsubscribe();
  }

  async open<A extends Gateway>(
    ownerId: number,
    acquire: () => Promise<A>,
  ): Promise<{ id: string; gateway: A }> {
    const owner = this.owners.get(ownerId);
    if (this.stopped || !owner?.alive || this.leases.size + this.pending >= 16)
      throw new Error("Gateway owner unavailable or capacity reached.");
    this.pending++;
    try {
      const gateway = await acquire();
      if (this.stopped || !owner.alive) {
        await gateway.close();
        throw new Error("Gateway owner closed during acquisition.");
      }
      const id = NodeCrypto.randomUUID();
      this.leases.set(id, { ownerId, gateway });
      return { id, gateway };
    } finally {
      this.pending--;
    }
  }

  async close(id: string, ownerId: number): Promise<void> {
    const lease = this.leases.get(id);
    if (!lease) return;
    if (lease.ownerId !== ownerId) throw new Error("Wrong gateway owner.");
    this.leases.delete(id);
    await lease.gateway.close();
  }

  async closeOwner(ownerId: number): Promise<void> {
    const owner = this.owners.get(ownerId);
    if (owner?.alive) {
      owner.alive = false;
      owner.unsubscribe();
    }
    const owned = [...this.leases].filter(([, lease]) => lease.ownerId === ownerId);
    for (const [id] of owned) this.leases.delete(id);
    await Promise.all(owned.map(([, lease]) => lease.gateway.close()));
  }

  async shutdown(): Promise<void> {
    this.stopped = true;
    await Promise.all([...this.owners.keys()].map((id) => this.closeOwner(id)));
  }
}
