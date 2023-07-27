import * as snarkJs from 'snarkjs'
import {buildEddsa, buildBabyjub, buildPoseidon} from 'circomlibjs'
import fs from 'fs';
import path from 'path'

const ZKEY_PATH =
  "../curcuit/ecdsaposeidon/circuit_final.zkey";
const VKEY_PATH = "../curcuit/ecdsaposeidon/verification_key.json";

const verify = async (proof, publicSignals) => {
  const vkeyPath = path.join(__dirname, VKEY_PATH)
  const vKey = JSON.parse(fs.readFileSync(vkeyPath));
  const result = await snarkJs.groth16.verify(
    vKey,
    publicSignals,
    proof,
    console
  );

  if (result) {
    console.log("Proof verified!");
  } else {
    console.log("Proof verification failed");
  }
};

async function generateProof(msgHash, privKey) {
  const zkeyPath = path.join(__dirname, ZKEY_PATH)
  if (!fs.existsSync(zkeyPath)) {
    console.log(
      "zkey not found."
    );
    return {};
  }

  console.time("Full proof generation");

  const ecdsa = await buildEddsa()
  const babyJub = await buildBabyjub();
  const { F } = babyJub;
  
  const pubKey = ecdsa.prv2pub(privKey.toString(16))

  const poseidon = await buildPoseidon()
  const msgPoseidon = poseidon([msgHash])
  const signature = ecdsa.signPoseidon(privKey.toString(16), msgPoseidon)

  const input = {
    enabled: 1,
    Ax: F.toObject(pubKey[0]),
    Ay: F.toObject(pubKey[1]),
    R8x: F.toObject(signature.R8[0]),
    R8y: F.toObject(signature.R8[1]),
    S:  signature.S,
    M:  F.toObject(msgPoseidon)
  };

  console.log("Proving...");
  const wasmPath = path.join(__dirname, "../curcuit/ecdsaposeidon/curcuit.wasm")
  const { publicSignals, proof } = await snarkJs.groth16.fullProve(
      input,
      wasmPath,
      zkeyPath
  );
  return { publicSignals, proof }
};

module.exports = {
    generateProof
}