// Guards against orphaned test files (issue #283): every test file under
// test/ must be picked up by a test-file glob in the `test` or `test:ui`
// npm script, so a new or moved file can never silently skip CI the way
// support-chat-core.test.ts once did.
import assert from "node:assert/strict";
import { globSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import test from "node:test";

const dashboardRoot = join(import.meta.dirname, "..");

function scriptTestPatterns(script: string): string[] {
  const patterns = [...script.matchAll(/--test\s+"([^"]+)"/g)].map((match) => match[1]);
  assert.ok(patterns.length > 0, `expected a quoted --test glob in: ${script}`);
  return patterns;
}

function testFilesOnDisk(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.test\.tsx?$/.test(entry.name))
    .map((entry) => relative(dashboardRoot, join(entry.parentPath, entry.name)).split(sep).join("/"));
}

test("every test file under test/ is run by an npm test script", () => {
  const { scripts } = JSON.parse(readFileSync(join(dashboardRoot, "package.json"), "utf8")) as {
    scripts: Record<string, string>;
  };
  const patterns = [...scriptTestPatterns(scripts.test), ...scriptTestPatterns(scripts["test:ui"])];
  const runFiles = new Set(
    patterns.flatMap((pattern) =>
      globSync(pattern, { cwd: dashboardRoot }).map((file) => file.split(sep).join("/")),
    ),
  );

  const onDisk = testFilesOnDisk(join(dashboardRoot, "test"));
  assert.ok(onDisk.includes("test/test-list.test.ts"), "the guard must find itself");
  const orphaned = onDisk.filter((file) => !runFiles.has(file)).sort();
  assert.deepEqual(orphaned, [], `test files not matched by any --test glob: ${orphaned.join(", ")}`);
});

test("the coverage script measures the full test suite", () => {
  const { scripts } = JSON.parse(readFileSync(join(dashboardRoot, "package.json"), "utf8")) as {
    scripts: Record<string, string>;
  };
  assert.equal(scripts["test:coverage"], "c8 npm test");
});
