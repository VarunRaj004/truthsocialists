pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "./domains.circom";

template ActiveMembership(depth) {
    signal input P;
    signal input D;
    signal input merkleSiblings[depth];
    signal input merklePathBits[depth];

    signal output root;
    signal output personAnchor;
    signal output activeDeviceHash;

    component personIsZero = IsZero();
    personIsZero.in <== P;
    personIsZero.out === 0;

    component deviceIsZero = IsZero();
    deviceIsZero.in <== D;
    deviceIsZero.out === 0;

    component person = Poseidon(2);
    person.inputs[0] <== domainPerson();
    person.inputs[1] <== P;
    personAnchor <== person.out;

    component device = Poseidon(2);
    device.inputs[0] <== domainDevice();
    device.inputs[1] <== D;
    activeDeviceHash <== device.out;

    component leaf = Poseidon(3);
    leaf.inputs[0] <== domainMemberLeaf();
    leaf.inputs[1] <== personAnchor;
    leaf.inputs[2] <== activeDeviceHash;

    signal hashes[depth + 1];
    signal left[depth];
    signal right[depth];
    component nodes[depth];
    hashes[0] <== leaf.out;

    for (var i = 0; i < depth; i++) {
        merklePathBits[i] * (merklePathBits[i] - 1) === 0;
        left[i] <== hashes[i] + merklePathBits[i] * (merkleSiblings[i] - hashes[i]);
        right[i] <== merkleSiblings[i] + merklePathBits[i] * (hashes[i] - merkleSiblings[i]);
        nodes[i] = Poseidon(3);
        nodes[i].inputs[0] <== domainMerkleNode();
        nodes[i].inputs[1] <== left[i];
        nodes[i].inputs[2] <== right[i];
        hashes[i + 1] <== nodes[i].out;
    }

    root <== hashes[depth];
}
