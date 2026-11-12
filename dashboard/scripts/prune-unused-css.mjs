// SPDX-License-Identifier: AGPL-3.0-only
// Conservative dead-selector sweep. Run from dashboard; --write applies it.
import fs from "node:fs";
import path from "node:path";
import postcss from "postcss";
import ts from "typescript";
function files(dir) { return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(path.join(dir, entry.name)) : /\.tsx?$/.test(entry.name) ? [path.join(dir, entry.name)] : []); }
const words = new Set();
const prefixes = [];
for (const file of files("src")) {
 const ast = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
 function visit(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
   for (const word of node.text.split(/\s+/)) if (/^[a-zA-Z_][\w-]*$/.test(word)) words.add(word);
   if ((ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isStringLiteral(node)) && /[\w-]-$/.test(node.text)) prefixes.push(node.text.split(/\s+/).at(-1));
  }
  ts.forEachChild(node, visit);
 }
 visit(ast);
}
const used = name => words.has(name) || prefixes.some(prefix => name.startsWith(prefix));
const file = "src/app/globals.css";
const root = postcss.parse(fs.readFileSync(file, "utf8"));
let removed = 0, kept = 0;
root.walkRules(rule => {
 // Ignore classes inside negations; a missing negative class doesn't make a selector dead.
 const selectors = postcss.list.comma(rule.selector).filter(selector => {
  const positive = selector.replace(/:not\([^)]*\)/g, "").replace(/\[[^\]]*\]/g, "");
  // Escaped/functional selectors need a full selector parser: keep conservatively.
  if (/\\|:(?:is|where|has)\(/.test(positive)) { kept++; return true; }
  const classes = [...positive.matchAll(/\.([a-zA-Z_][\w-]*)/g)].map(match => match[1]);
  const retain = classes.every(used); if (retain) kept++; else removed++; return retain;
 });
 if (selectors.length) rule.selector = selectors.join(", "); else rule.remove();
});
let changed;
do { changed = false; root.walkAtRules(rule => { if (rule.nodes && !rule.nodes.some(node => node.type !== "comment")) { rule.remove(); changed = true; } }); } while (changed);
if (process.argv.includes("--write")) fs.writeFileSync(file, root.toString());
console.log(JSON.stringify({ removedSelectors: removed, retainedSelectors: kept, dynamicPrefixes: [...new Set(prefixes)] }));
