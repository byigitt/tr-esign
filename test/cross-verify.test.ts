// Tüm reference/out/*.xml MA3 fixture'larını verify() ile doğrula.
// Her fixture için ayrı test case — hangisi geçiyor, hangisi neden geçmiyor net olsun.
//
// Beklentiler (docs/02-fixtures.md'deki gözlemlerle):
//   enveloping-bes.xml → BES, tam geçer
//   enveloped-bes.xml  → BES, ama MA3'ün kendi "enveloped" çıktısı aslında
//                        enveloping-embedded (aynı yapı + envelope içinde),
//                        verify mantığı aynı olmalı
//   detached-bes.xml   → BES, data reference external dosya ("sample-invoice.xml")
//                        olduğundan v0.1 verify'ımız external URI çözmüyor →
//                        beklenen sonuç: invalid("URI çözümlenemedi")

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { verify } from "../src/verify.ts";

const REF_OUT = join(import.meta.dirname, "..", "reference", "out");

function listFixtures(): string[] {
	try {
		return readdirSync(REF_OUT).filter((n) => n.endsWith(".xml"));
	} catch {
		return [];
	}
}

const fixtures = listFixtures();

test("cross-verify — at least one MA3 fixture available",
	{ skip: fixtures.length === 0 && "run reference/run.sh" },
	() => {
		assert.ok(fixtures.length > 0);
	});

test("cross-verify — enveloping-bes.xml",
	{ skip: !fixtures.includes("enveloping-bes.xml") && "fixture missing" },
	async () => {
		const xml = readFileSync(join(REF_OUT, "enveloping-bes.xml"), "utf8");
		const r = await verify(xml);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
	});

test("cross-verify — enveloped-bes.xml (MA3 enveloping-embedded variant)",
	{ skip: !fixtures.includes("enveloped-bes.xml") && "fixture missing" },
	async () => {
		const xml = readFileSync(join(REF_OUT, "enveloped-bes.xml"), "utf8");
		const r = await verify(xml);
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
	});

test("cross-verify — detached-bes.xml (no resolver → invalid)",
	{ skip: !fixtures.includes("detached-bes.xml") && "fixture missing" },
	async () => {
		const xml = readFileSync(join(REF_OUT, "detached-bes.xml"), "utf8");
		const r = await verify(xml);
		assert.equal(r.valid, false);
		if (r.valid) return;
		assert.match(r.reason, /URI çözümlenemedi|Reference digest/);
	});

test("cross-verify — detached-bes.xml (with file-system resolver → valid)",
	{ skip: !fixtures.includes("detached-bes.xml") && "fixture missing" },
	async () => {
		const { readFileSync: read } = await import("node:fs");
		const { join: j } = await import("node:path");
		const FIXTURES = j(import.meta.dirname, "..", "reference", "fixtures");
		const xml = readFileSync(join(REF_OUT, "detached-bes.xml"), "utf8");
		const r = await verify(xml, {
			resolver: (uri) => {
				// MA3 detached örneğinin URI'si dosya adıdır ("sample-invoice.xml").
				if (uri.startsWith("http")) return null;
				return new Uint8Array(read(j(FIXTURES, uri)));
			},
		});
		assert.equal(r.valid, true, r.valid ? "" : `invalid: ${r.reason}`);
		if (!r.valid) return;
		assert.equal(r.level, "BES");
	});
