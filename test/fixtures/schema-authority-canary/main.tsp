// Independently authored TypeSpec authority for the repository-local parity canary.
// JSON Schema B generated from this file is comparison evidence only.
import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace OreSchemaAuthority;

@id("AuthorityKind")
enum AuthorityKind {
  typespec: "typespec",
  jsonSchema: "json-schema",
}

@id("PeerAuthorityRegistration")
model PeerAuthorityRegistration {
  repository: string;
  authority: AuthorityKind;
  generatedWitnessOnly: boolean;
  owner?: string;
}
