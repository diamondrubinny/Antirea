/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Compile-time tests for the typed client. Never executed: `npm test` runs
 * `tsc --noEmit` on it. A `@ts-expect-error` line fails the build if the error
 * it expects disappears, so each one pins a mistake the types must catch.
 */
// Values in this file exist only to carry types into the assertions.
/* eslint-disable @typescript-eslint/no-unused-vars */
import { createSecureClient, type ArgsOf, type ResultOf } from "../src/client.js";
import type { InvokeContext } from "../src/core.js";

const functions = {
  pricing: (args: { x: number }) => args.x * 1337 + 17,
  lookup: async (args: { id: string }, ctx: InvokeContext) => ({ id: args.id, calls: ctx.invokeCount }),
  ping: () => "pong" as const,
  search: (args?: { q?: string }) => [args?.q ?? ""],
};
type Api = typeof functions;

type Equal<A, B> = (<X>() => X extends A ? 1 : 2) extends <X>() => X extends B ? 1 : 2 ? true : false;
const assertType = <T extends true>(): T | undefined => undefined;

assertType<Equal<ArgsOf<Api["pricing"]>, { x: number }>>();
assertType<Equal<ResultOf<Api["lookup"]>, { id: string; calls: number }>>();

export async function typed(): Promise<void> {
  const api = createSecureClient<Api>({ endpoint: "/secure" });

  const price = await api.call("pricing", { x: 2 });
  assertType<Equal<typeof price, number>>();

  // An async server function resolves to its inner type, not Promise<Promise<…>>.
  const row = await api.call("lookup", { id: "a" });
  assertType<Equal<typeof row, { id: string; calls: number }>>();

  const pong = await api.call("ping");
  assertType<Equal<typeof pong, "pong">>();

  // Optional argument: both forms compile.
  await api.call("search");
  await api.call("search", { q: "x" });

  // @ts-expect-error unknown function name
  await api.call("pricng", { x: 2 });
  // @ts-expect-error wrong argument type
  await api.call("pricing", { x: "2" });
  // @ts-expect-error missing required argument
  await api.call("pricing");
  // @ts-expect-error extra argument for a function that takes none
  await api.call("ping", { x: 1 });
  // @ts-expect-error result is a number, not a string
  const wrong: string = await api.call("pricing", { x: 2 });
  void wrong;

  // The untyped `invoke` still works, for callers without a shared type.
  const loose = await api.invoke<number>("pricing", { x: 2 });
  assertType<Equal<typeof loose, number>>();
}

export async function untyped(): Promise<void> {
  // Without a type parameter the client accepts any name, as before.
  const api = createSecureClient({ endpoint: "/secure" });
  const anything = await api.call("whatever", { a: 1 });
  assertType<Equal<typeof anything, unknown>>();
}
