export interface PhaseTwoContribution {
  readonly index: number;
  readonly name: string;
}

const ANSI_ESCAPE = /\u001b\[[0-9;]*m/g;

export function parsePhaseTwoContributions(snarkjsVerificationOutput: string): PhaseTwoContribution[] {
  const normalized = snarkjsVerificationOutput.replace(ANSI_ESCAPE, "").replaceAll("\r\n", "\n");
  const contributions: PhaseTwoContribution[] = [];
  const pattern = /contribution #(\d+)\s+([^:\n]+):/g;
  for (const match of normalized.matchAll(pattern)) {
    contributions.push({ index: Number(match[1]), name: match[2]!.trim() });
  }
  return contributions;
}

export function assertProductionPhaseTwoTranscript(
  snarkjsVerificationOutput: string,
): readonly PhaseTwoContribution[] {
  const normalized = snarkjsVerificationOutput.replace(ANSI_ESCAPE, "");
  if (!normalized.includes("ZKey Ok!")) throw new Error("snarkjs did not report ZKey Ok!");
  const contributions = parsePhaseTwoContributions(normalized);
  const people = contributions.filter(({ index }) => index >= 1 && index <= 3);
  if (people.length !== 3 || people.some(({ index }, offset) => index !== offset + 1)) {
    throw new Error("phase two must contain contributions #1, #2, and #3");
  }
  const names = new Set(people.map(({ name }) => name.normalize("NFC").trim().toLocaleLowerCase("en-US")));
  if (names.size !== 3) throw new Error("phase-two contributor names must be distinct");
  if (people.some(({ name }) => /development|insecure|test/i.test(name))) {
    throw new Error("development or test contributions cannot be published");
  }
  const beacon = contributions.find(({ index }) => index === 4);
  if (beacon?.name !== "Cyber Cipher public final beacon") {
    throw new Error("the fourth contribution must be the declared Cyber Cipher public final beacon");
  }
  return contributions;
}
