import { loadHostSeed, type HostKeyBackend } from "@t3tools/iroh/keys";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";

export class HostKeyStoreError extends Schema.TaggedError<HostKeyStoreError>()(
  "HostKeyStoreError",
  {
    backend: Schema.Literals(["file", "systemd-credential"]),
    cause: Schema.Defect(),
  },
) {
  override get message(): string {
    return "Cannot load Iroh host identity. Identity was not replaced and no fallback was attempted.";
  }
}

export class HostKeyStore extends Context.Service<
  HostKeyStore,
  {
    readonly status: {
      readonly backend: "file" | "systemd-credential";
      readonly hardwareSigning: false;
    };
    readonly load: Effect.Effect<Uint8Array, HostKeyStoreError>;
  }
>()("t3/iroh/HostKeyStore") {}

export const layer = (backend: HostKeyBackend) =>
  Layer.succeed(
    HostKeyStore,
    HostKeyStore.of({
      status: { backend: backend.kind, hardwareSigning: false },
      load: Effect.try({
        try: () => loadHostSeed(backend),
        catch: (cause) => new HostKeyStoreError({ backend: backend.kind, cause }),
      }),
    }),
  );
