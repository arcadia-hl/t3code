// Retain admission until the native handshake settles, including after a timeout.
// Revocation tombstones cover renewal callbacks that arrive after removal commits.
export class TransportAdmission<C extends { close(code: bigint, reason: number[]): void }> {
  readonly connections = new Map<C, string | undefined>();
  private readonly revoked = new Set<string>();
  private handshakes = 0;
  private controls = 0;
  private readonly connectionLimit: number;
  private readonly controlLimit: number;
  constructor(connectionLimit = 32, controlLimit = 64) {
    this.connectionLimit = connectionLimit;
    this.controlLimit = controlLimit;
  }

  private release(action: () => void): () => void {
    let done = false;
    return () => {
      if (!done) {
        done = true;
        action();
      }
    };
  }
  handshake(): (() => void) | undefined {
    if (this.connections.size + this.handshakes >= this.connectionLimit) return;
    this.handshakes++;
    return this.release(() => {
      this.handshakes--;
    });
  }
  control(): (() => void) | undefined {
    if (this.controls >= this.controlLimit) return;
    this.controls++;
    return this.release(() => {
      this.controls--;
    });
  }
  accept(connection: C): boolean {
    if (this.connections.size >= this.connectionLimit) {
      connection.close(1n, []);
      return false;
    }
    this.connections.set(connection, undefined);
    return true;
  }
  authorize(connection: C, deviceId: string): boolean {
    if (!this.connections.has(connection) || this.revoked.has(deviceId)) {
      connection.close(1n, []);
      return false;
    }
    this.connections.set(connection, deviceId);
    return true;
  }
  device(connection: C): string | undefined {
    return this.connections.get(connection);
  }
  remove(connection: C): void {
    this.connections.delete(connection);
  }
  revoke(deviceId: string): void {
    this.revoked.add(deviceId);
    for (const [connection, id] of this.connections)
      if (id === deviceId) {
        this.connections.delete(connection);
        connection.close(1n, []);
      }
  }
}
