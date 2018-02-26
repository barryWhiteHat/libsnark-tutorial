# libsnark-ethereum-tutorial
Ethereum Wrapper libsnark zksnarks

## build instructions:
See https://github.com/howardwu/libsnark-tutorial#build-guide for build instructions

After building libsnark `cd snarkWrapper` and `npm install`

## Deploy contract:
To deploy contract `cd ./snarkWrapper` and run `node deploy.js` 

## To rebuild zksnark\_element:
`cd ./zksnark_element` and run `../build/src/main` this will create `vk.json` and `proof.json`
which are used by the sample contract. 
