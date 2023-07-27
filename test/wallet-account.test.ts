import { Wallet, BigNumber} from 'ethers'
import { ethers } from 'hardhat'
import { expect } from 'chai'
import {
  ERC1967Proxy__factory,
  WalletAccount,
  WalletAccount__factory,
  WalletAccountFactory,
  WalletAccountFactory__factory,
  TraditionalEcdsaValidator,
  TraditionalEcdsaValidator__factory,
  VerifierEcdsaWrapper__factory,
  ZkEcdsaValidator,
  ZkEcdsaValidator__factory,
  TestUtil,
  TestUtil__factory
} from '../typechain'
import {
  createAccount,
  createAddress,
  createAccountOwner,
  deployEntryPoint,
  getBalance,
  isDeployed,
  ONE_ETH,
  HashZero
} from './testutils'
import { fillUserOpDefaults, getUserOpHash, packUserOp, signUserOp } from './UserOp'
import { 
    parseEther,
    arrayify,
    defaultAbiCoder,
    hexDataSlice,
    keccak256
} from 'ethers/lib/utils'
import { UserOperation } from './UserOperation'
import { generateProof } from './helpers/zkEcdsaPoseidon'
import { Create2Factory } from '../src/Create2Factory'
import { poseidonContract } from 'circomlibjs'

// Deploys an implementation and a proxy pointing to this implementation
async function createWalletAccount (
    ethersSigner: Signer,
    accountOwner: string,
    entryPoint: string,
    _factory?: WalletAccountFactory
  ):
    Promise<{
      proxy: WalletAccount
      accountFactory: WalletAccountFactory
      implementation: string
    }> {
    const validator = await deployTraditionValidator()
    const accountFactory = _factory ?? await new WalletAccountFactory__factory(ethersSigner).deploy(entryPoint, validator.address, accountOwner)

    const implementation = await accountFactory.accountImplementation()
    await accountFactory.createAccount(accountOwner, 0)
    const accountAddress = await accountFactory.getAddress(accountOwner, 0)
    const proxy = WalletAccount__factory.connect(accountAddress, ethersSigner)
    return {
      implementation,
      accountFactory,
      proxy
    }
}

async function deployTraditionValidator (provider = ethers.provider): Promise<TraditionalEcdsaValidator> {
    const create2factory = new Create2Factory(provider)
    const epf = new TraditionalEcdsaValidator__factory(provider.getSigner())
    const addr = await create2factory.deploy(epf.bytecode, 0, process.env.COVERAGE != null ? 20e6 : 8e6)
    return TraditionalEcdsaValidator__factory.connect(addr, provider.getSigner())
}

async function deployZkValidator (poseidonAddr : address, provider = ethers.provider): Promise<string> {
    let create2factory = new Create2Factory(provider)
    let epf = new ZkEcdsaValidator__factory({["contracts/lib/Poseidon.sol:PoseidonUnit1L"]: poseidonAddr}, provider.getSigner())
    let addr = await create2factory.deploy(epf.bytecode, 0, process.env.COVERAGE != null ? 20e6 : 8e6)
    const zkValidator = ZkEcdsaValidator__factory.connect(addr, provider.getSigner())
    epf = new VerifierEcdsaWrapper__factory(provider.getSigner())
    addr = await create2factory.deploy(epf.bytecode, 0, process.env.COVERAGE != null ? 20e6 : 8e6)
    await zkValidator.initialize(addr)
    return zkValidator.address
}

async function deployPoseidon(provider = ethers.provider) :Promise<address> {
    const abi = poseidonContract.generateABI(1)
    const code = poseidonContract.createCode(1)
    let poseidon1 = new ethers.ContractFactory(abi, code, provider.getSigner());
    poseidon1 = await poseidon1.deploy()
    await poseidon1.deployed()
    console.log("+++++++++++++poseidon1+++++++++++++++ ", poseidon1.address)
    return poseidon1.address
}

async function packZkSignature(msgHash, privKey) : Promise<{encodedProof: string, pubKey: string}> {
    var {publicSignals, proof} = await generateProof(msgHash, privKey)

    var encodedProof = defaultAbiCoder.encode(['uint256[]', 'uint256[2]', 'uint256[2][2]', 'uint256[2]'], 
      [
        publicSignals.map((p)=>p.toString()), 
        proof.pi_a.slice(0, 2), 
        [
          [proof.pi_b[0][1].toString(), proof.pi_b[0][0].toString()],
          [proof.pi_b[1][1].toString(), proof.pi_b[1][0].toString()]
        ],
        proof.pi_c.slice(0, 2)
      ]
    )

    encodedProof = defaultAbiCoder.encode(['uint256', 'bytes'], ['0x37106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684', encodedProof])

    const pubKey = keccak256(defaultAbiCoder.encode(['uint256', 'uint256'],[publicSignals[0].toString(), publicSignals[1].toString()]))

    return {encodedProof, pubKey}
}

describe('WalletAccount', function () {
  let entryPoint: string
  let accounts: string[]
  let testUtil: TestUtil
  let accountOwner: Wallet
  let zkValidator: string
  const ethersSigner = ethers.provider.getSigner()
  const privKey = BigInt(
    "0xf5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f"
  )

  const privKey1 = BigInt(
    "0xe5b552f609f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f"
  )

  before(async function () {
    entryPoint = await deployEntryPoint().then(e => e.address)
    accounts = await ethers.provider.listAccounts()
    // ignore in geth.. this is just a sanity test. should be refactored to use a single-account mode..
    if (accounts.length < 2) this.skip()
    testUtil = await new TestUtil__factory(ethersSigner).deploy()
    accountOwner = createAccountOwner()
    const poseidon = await deployPoseidon()
    console.log(poseidon)
    zkValidator = await deployZkValidator(poseidon)
  })

  it('owner should be able to call transfer', async () => {
    const { proxy: account } = await createWalletAccount(ethers.provider.getSigner(), accounts[0], entryPoint)
    await ethersSigner.sendTransaction({ from: accounts[0], to: account.address, value: parseEther('2') })
    await account.execute(accounts[2], ONE_ETH, '0x')
  })
  it('other account should not be able to call transfer', async () => {
    const { proxy: account } = await createWalletAccount(ethers.provider.getSigner(), accounts[0], entryPoint)
    await expect(account.connect(ethers.provider.getSigner(1)).execute(accounts[2], ONE_ETH, '0x'))
      .to.be.revertedWith('account: not Owner or EntryPoint')
  })

  it('should pack in js the same as solidity', async () => {
    const op = await fillUserOpDefaults({ sender: accounts[0] })
    const packed = packUserOp(op)
    expect(await testUtil.packUserOp(op)).to.equal(packed)
  })

  describe('#changeMaterial', () => {
    let account: WalletAccount
    let walletAccountFactory: WalletAccountFactory
    let accountOwner1: Wallet
    const actualGasPrice = 1e9
    // for testing directly validateUserOp, we initialize the account with EOA as entryPoint.
    let chainId: number
    let userOp:UserOperation
    let expectedPay: number
    
    before(async () => {
        ({
            proxy: account,
            accountFactory: walletAccountFactory
        } = await createWalletAccount(ethersSigner, await accountOwner.getAddress(), await accountOwner.getAddress()))
        
        accountOwner1 = createAccountOwner()
        await ethersSigner.sendTransaction({ from: accounts[0], to: account.address, value: parseEther('0.2') })
        await ethersSigner.sendTransaction({ from: accounts[0], to: await accountOwner.getAddress(), value: parseEther('0.2') })
        await ethersSigner.sendTransaction({ from: accounts[0], to: await accountOwner1.getAddress(), value: parseEther('0.2') })

        chainId = await ethers.provider.getNetwork().then(net => net.chainId)
        userOp = fillUserOpDefaults({
            sender: account.address,
            callGasLimit:200000,//callGasLimit,
            verificationGasLimit:100000,//verificationGasLimit,
            maxFeePerGas:3e9//maxFeePerGas
        })

        await walletAccountFactory.bindValidator(zkValidator)
        const opHash = await getUserOpHash(userOp, entryPoint, chainId)
        const {encodedProof:proof, pubKey: material} = await packZkSignature(opHash, privKey)
        const grantAction = account.interface.encodeFunctionData(
          'grant', 
          [
              '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
              '0x37106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684',
              material
          ]
        )
        
        await account.connect(accountOwner).execute(account.address, 0, grantAction)
    })

    it('change material and traditional validator', async () => {
      // traditional validator
      let changeMaterial = account.interface.encodeFunctionData(
        'changeMaterial', 
        [
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            await accountOwner1.getAddress()
        ]
        )
      await expect(account.connect(accountOwner).execute(account.address, 0, changeMaterial)).to.be.revertedWith('root validator can not modify')
      let userOpHash = await getUserOpHash(userOp, entryPoint, chainId)
      let signedUserOp = signUserOp(userOp, accountOwner1, entryPoint, chainId, '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa')
      
      await expect(account.connect(accountOwner).validateUserOp(signedUserOp, userOpHash, 0)).to.be.revertedWith('fail to validate')

      signedUserOp = signUserOp(userOp, accountOwner, entryPoint, chainId, '0x3daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa')
      await expect(account.connect(accountOwner).validateUserOp(signedUserOp, userOpHash, 0)).to.be.revertedWith('validator has not been granted')

    //   signedUserOp = signUserOp(userOp, accountOwner1, entryPoint, chainId, '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa')
    //   await account.connect(accountOwner).validateUserOp(signedUserOp, userOpHash, 0)
      // change material
      changeMaterial = account.interface.encodeFunctionData(
        'changeMaterial', 
        [
            '0x4daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            await accountOwner1.getAddress()
        ]
        )
       await expect(account.connect(accountOwner).execute(account.address, 0, changeMaterial)).to.be.revertedWith('validator has not been granted')
    })

    it('change material and zk validator', async () => {        
        // zk validator
        let userOpHash = await getUserOpHash(userOp, entryPoint, chainId)
        const {encodedProof:proof, pubKey: material} = await packZkSignature(userOpHash, privKey)
        const {encodedProof:proof1, pubKey: material1} = await packZkSignature(userOpHash, privKey1)
        await account.connect(accountOwner).validateUserOp({...userOp, signature: proof}, userOpHash, 0)
        let changeMaterial = account.interface.encodeFunctionData(
          'changeMaterial', 
          [
              '0x37106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684',
              material1
          ]
          )
        await account.connect(accountOwner).execute(account.address, 0, changeMaterial)
        await expect(account.connect(accountOwner).validateUserOp({...userOp, signature: proof}, userOpHash, 0)).to.be.revertedWith('fail to validate')
        await account.connect(accountOwner).validateUserOp({...userOp, signature: proof1}, userOpHash, 0)
      })
  })

  describe('#grant', () => {
    let account: WalletAccount
    let walletAccountFactory: WalletAccountFactory
    let accountOwner1: Wallet
    const actualGasPrice = 1e9
    // for testing directly validateUserOp, we initialize the account with EOA as entryPoint.
    let chainId: number
    let userOp:UserOperation
    let expectedPay: number
    
    before(async () => {
      ({
        proxy: account,
        accountFactory: walletAccountFactory
      } = await createWalletAccount(ethersSigner, await accountOwner.getAddress(), await accountOwner.getAddress()))
    
      accountOwner1 = createAccountOwner()
      await ethersSigner.sendTransaction({ from: accounts[0], to: account.address, value: parseEther('0.2') })
      await ethersSigner.sendTransaction({ from: accounts[0], to: await accountOwner.getAddress(), value: parseEther('0.2') })
      await ethersSigner.sendTransaction({ from: accounts[0], to: await accountOwner1.getAddress(), value: parseEther('0.2') })

      chainId = await ethers.provider.getNetwork().then(net => net.chainId)
      userOp = fillUserOpDefaults({
            sender: account.address,
            callGasLimit:200000,//callGasLimit,
            verificationGasLimit:100000,//verificationGasLimit,
            maxFeePerGas:3e9//maxFeePerGas
        })
    })

    it('grant', async () => {
      const userOpHash = await getUserOpHash(userOp, entryPoint, chainId)
      let grantAction = account.interface.encodeFunctionData(
        'grant', 
        [
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            await accountOwner1.getAddress()
        ]
      )
      await expect(account.connect(accountOwner).execute(account.address, 0, grantAction)).to.be.revertedWith('validator should be different')

      grantAction = account.interface.encodeFunctionData(
        'grant', 
        [
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            '0x3daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            await accountOwner1.getAddress()
        ]
      )
      await expect(account.connect(accountOwner).execute(account.address, 0, grantAction)).to.be.revertedWith('validator is not existed')

      grantAction = account.interface.encodeFunctionData(
        'grant', 
        [
            '0x3daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            await accountOwner1.getAddress()
        ]
      )
      await expect(account.connect(accountOwner).execute(account.address, 0, grantAction)).to.be.revertedWith('validator has not been granted')
      await walletAccountFactory.bindValidator(zkValidator)
      const {encodedProof:proof, pubKey: material} = await packZkSignature(userOpHash, privKey)
      grantAction = account.interface.encodeFunctionData(
        'grant', 
        [
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            '0x37106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684',
            material
        ]
      )
      
      await account.connect(accountOwner).execute(account.address, 0, grantAction)

      grantAction = account.interface.encodeFunctionData(
        'grant', 
        [
            '0x37106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684',
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            material
        ]
      )
      
      await expect(account.connect(accountOwner).execute(account.address, 0, grantAction)).to.be.revertedWith('validator has been granted')
      const ret = await account.connect(accountOwner).validateUserOp({...userOp, signature: proof}, userOpHash, 0)
      await ret.wait()
    })
  })

  describe('#revoke', () => {
    let account: WalletAccount
    let walletAccountFactory: WalletAccountFactory
    let accountOwner1: Wallet
    const actualGasPrice = 1e9
    // for testing directly validateUserOp, we initialize the account with EOA as entryPoint.
    let chainId: number
    let userOp:UserOperation
    let expectedPay: number
    
    before(async () => {
      ({
        proxy: account,
        accountFactory: walletAccountFactory
      } = await createWalletAccount(ethersSigner, await accountOwner.getAddress(), await accountOwner.getAddress()))
    
      accountOwner1 = createAccountOwner()
      await ethersSigner.sendTransaction({ from: accounts[0], to: account.address, value: parseEther('0.2') })
      await ethersSigner.sendTransaction({ from: accounts[0], to: await accountOwner.getAddress(), value: parseEther('0.2') })
      await ethersSigner.sendTransaction({ from: accounts[0], to: await accountOwner1.getAddress(), value: parseEther('0.2') })

      chainId = await ethers.provider.getNetwork().then(net => net.chainId)
      userOp = fillUserOpDefaults({
            sender: account.address,
            callGasLimit:200000,//callGasLimit,
            verificationGasLimit:100000,//verificationGasLimit,
            maxFeePerGas:3e9//maxFeePerGas
      })

      await walletAccountFactory.bindValidator(zkValidator)
      const opHash = await getUserOpHash(userOp, entryPoint, chainId)
      const {encodedProof:proof, pubKey: material} = await packZkSignature(opHash, privKey)
      const grantAction = account.interface.encodeFunctionData(
        'grant', 
        [
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            '0x37106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684',
            material
        ]
      )
      
      await account.connect(accountOwner).execute(account.address, 0, grantAction)
    })

    it('revoke', async () => {
      const userOpHash = await getUserOpHash(userOp, entryPoint, chainId)
      let revokeAction = account.interface.encodeFunctionData(
        'revoke', 
        [
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa'
        ]
      )
      await expect(account.connect(accountOwner).execute(account.address, 0, revokeAction)).to.be.revertedWith('validator should be different')

      revokeAction = account.interface.encodeFunctionData(
        'revoke', 
        [
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            '0x3daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa'
        ]
      )
      await expect(account.connect(accountOwner).execute(account.address, 0, revokeAction)).to.be.revertedWith('validator has been revoked')

      revokeAction = account.interface.encodeFunctionData(
        'revoke', 
        [
            '0x37106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684',
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa'
        ]
      )

      await expect(account.connect(accountOwner).execute(account.address, 0, revokeAction)).to.be.revertedWith('validator has been revoked')

      revokeAction = account.interface.encodeFunctionData(
        'revoke', 
        [
            '0x47106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684',
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa'
        ]
      )

      await expect(account.connect(accountOwner).execute(account.address, 0, revokeAction)).to.be.revertedWith('validator has not been granted')

      revokeAction = account.interface.encodeFunctionData(
        'revoke',
        [
            '0x2daa737e13c50c4bbce0e98ee727347a0b510c39a5766854fc1e579342d095aa',
            '0x37106196440789755adfccc3a57770fecef1eaca423ca7d75f34dab84d344684'
            
        ]
      )

      await account.connect(accountOwner).execute(account.address, 0, revokeAction)
      await expect(account.connect(accountOwner).execute(account.address, 0, revokeAction)).to.be.revertedWith('validator has been revoked')
      const {encodedProof:proof, pubKey: material} = await packZkSignature(userOpHash, privKey)
      await expect(account.connect(accountOwner).validateUserOp({...userOp, signature: proof}, userOpHash, 0)).to.be.revertedWith('validator has not been granted')
    })
  })

//   context('WalletAccountFactory', () => {
//     it('sanity: check deployer', async () => {
//       const ownerAddr = createAddress()
//       const deployer = await new WalletAccountFactory__factory(ethersSigner).deploy(entryPoint)
//       const target = await deployer.callStatic.createAccount(ownerAddr, 1234)
//       expect(await isDeployed(target)).to.eq(false)
//       await deployer.createAccount(ownerAddr, 1234)
//       expect(await isDeployed(target)).to.eq(true)
//     })
//   })
})