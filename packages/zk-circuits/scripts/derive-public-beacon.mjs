import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const [pulsePath, notBeforeValue] = process.argv.slice(2);
if (!pulsePath) throw new TypeError("path to an archived NIST Beacon pulse JSON is required");
if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(notBeforeValue ?? "")) {
  throw new TypeError("not-before must be an explicit UTC timestamp such as 2026-10-04T12:00:00.000Z");
}
const document = JSON.parse(await readFile(pulsePath, "utf8"));
const pulse = document?.pulse;
if (pulse?.version !== "2.0" || pulse?.statusCode !== 0) throw new Error("NIST Beacon pulse is not a successful v2 pulse");
if (!/^https:\/\/beacon\.nist\.gov\/beacon\/2\.0\/chain\/\d+\/pulse\/\d+$/.test(pulse.uri ?? "")) {
  throw new Error("unexpected NIST Beacon pulse URI");
}
const pulseTime = Date.parse(pulse.timeStamp);
const notBefore = Date.parse(notBeforeValue);
if (!Number.isFinite(pulseTime) || pulseTime < notBefore) throw new Error("pulse predates the committed not-before time");
if (!/^[0-9a-f]{128}$/i.test(pulse.outputValue ?? "")) throw new Error("pulse outputValue must contain 512 bits");
if (!/^[0-9a-f]+$/i.test(pulse.signatureValue ?? "")) throw new Error("pulse signature is missing");

const output = Buffer.from(pulse.outputValue, "hex");
const beacon = createHash("sha256").update(output).digest("hex");
const sourceDocumentSha256 = createHash("sha256").update(await readFile(pulsePath)).digest("hex");
process.stdout.write(`${JSON.stringify({
  beacon,
  derivation: "SHA-256(NIST Beacon v2 pulse.outputValue bytes)",
  pulseUri: pulse.uri,
  pulseTime: pulse.timeStamp,
  notBefore: notBeforeValue,
  sourceDocumentSha256,
}, null, 2)}\n`);
