BUILD_DIR=./build/

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR"
else
    rm -fr $BUILD_DIR
fi

cd $BUILD_DIR
snarkjs powersoftau new bn128 20 pot20_0000.ptau -v
snarkjs powersoftau contribute pot20_0000.ptau pot20_0001.ptau --name="First contribution" -v -e="hello123"
snarkjs powersoftau contribute pot20_0001.ptau pot20_0002.ptau --name="Second contribution" -v -e="hello123"
snarkjs powersoftau export challenge pot20_0002.ptau challenge_0003
snarkjs powersoftau challenge contribute bn128 challenge_0003 response_0003 -e="hello123"
snarkjs powersoftau import response pot20_0002.ptau response_0003 pot20_0003.ptau -n="Third contribution name"
snarkjs powersoftau verify pot20_0003.ptau
snarkjs powersoftau beacon pot20_0003.ptau pot20_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"
snarkjs powersoftau prepare phase2 pot20_beacon.ptau pot20_final.ptau -v