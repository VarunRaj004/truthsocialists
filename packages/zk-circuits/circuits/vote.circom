pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "./active_membership.circom";

template VoteProof(depth) {
    // Public signals: keep this declaration order aligned with main's public list.
    signal input membershipRoot;
    signal input epoch;
    signal input complaintIdField;
    signal input voteNullifier;
    signal input voteChoice;
    signal input voteMessageCommitment;
    signal input challengeField;

    signal input P;
    signal input D;
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

    component nullifier = Poseidon(3);
    nullifier.inputs[0] <== domainVoteNullifier();
    nullifier.inputs[1] <== P;
    nullifier.inputs[2] <== complaintIdField;
    nullifier.out === voteNullifier;

    component message = Poseidon(3);
    message.inputs[0] <== domainVoteMessage();
    message.inputs[1] <== complaintIdField;
    message.inputs[2] <== voteChoice;
    message.out === voteMessageCommitment;

    component epochBits = Num2Bits(64);
    epochBits.in <== epoch;
    component choiceBits = Num2Bits(2);
    choiceBits.in <== voteChoice;
    component challengeBits = Num2Bits(254);
    challengeBits.in <== challengeField;
}

component main {public [
    membershipRoot,
    epoch,
    complaintIdField,
    voteNullifier,
    voteChoice,
    voteMessageCommitment,
    challengeField
]} = VoteProof(16);
