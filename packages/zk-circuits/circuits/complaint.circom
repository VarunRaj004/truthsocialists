pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "./active_membership.circom";

template ComplaintProof(depth) {
    // Public signals: keep this declaration order aligned with main's public list.
    signal input membershipRoot;
    signal input epoch;
    signal input matterField;
    signal input serialField;
    signal input personCommitment;
    signal input complaintNullifier;
    signal input complaintCommitmentField;
    signal input challengeField;

    signal input P;
    signal input D;
    signal input r;
    signal input merkleSiblings[depth];
    signal input merklePathBits[depth];

    component membership = ActiveMembership(depth);
    membership.P <== P;
    membership.D <== D;
    for (var i = 0; i < depth; i++) {
        membership.merkleSiblings[i] <== merkleSiblings[i];
        membership.merklePathBits[i] <== merklePathBits[i];
    }
    membership.root === membershipRoot;

    component randomnessIsZero = IsZero();
    randomnessIsZero.in <== r;
    randomnessIsZero.out === 0;

    component entitlement = Poseidon(3);
    entitlement.inputs[0] <== domainEntitlementPerson();
    entitlement.inputs[1] <== P;
    entitlement.inputs[2] <== r;
    entitlement.out === personCommitment;

    component nullifier = Poseidon(3);
    nullifier.inputs[0] <== domainComplaintNullifier();
    nullifier.inputs[1] <== P;
    nullifier.inputs[2] <== matterField;
    nullifier.out === complaintNullifier;

    // These decompositions make every externally compared pass-through value
    // participate in the relation, while also enforcing the epoch's uint64 range.
    component epochBits = Num2Bits(64);
    epochBits.in <== epoch;
    component serialBits = Num2Bits(254);
    serialBits.in <== serialField;
    component commitmentBits = Num2Bits(254);
    commitmentBits.in <== complaintCommitmentField;
    component challengeBits = Num2Bits(254);
    challengeBits.in <== challengeField;
}

component main {public [
    membershipRoot,
    epoch,
    matterField,
    serialField,
    personCommitment,
    complaintNullifier,
    complaintCommitmentField,
    challengeField
]} = ComplaintProof(16);
