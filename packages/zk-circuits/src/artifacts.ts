import {
  artifactManifest,
  bytesToHex,
  encodeCanonical,
  sha256,
  type ArtifactManifestInput,
} from "@cyber-cipher/protocol-core";

export interface EncodedArtifactManifest {
  readonly bytes: Uint8Array;
  readonly artifactId: Uint8Array;
  readonly artifactIdHex: string;
}

export function encodeArtifactManifest(input: ArtifactManifestInput): EncodedArtifactManifest {
  const bytes = encodeCanonical(artifactManifest(input));
  const artifactId = sha256(bytes);
  return { bytes, artifactId, artifactIdHex: bytesToHex(artifactId) };
}
