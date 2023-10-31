# ERC-4337 Accout Abstraction Tutorial
I could not find a good tutorial for those who want to go deeper into the technical details of
ERC-4337 Account Abstraction and how to use it. So I decided to do one myself.

To get a firt overview what EIP-4337 is about and what it is used for I found this article quiete helpful [medium blog post](https://medium.com/blockchain-at-usc/deep-dive-into-account-abstraction-and-eip-4337-scaling-ethereum-ux-from-0-to-1-c2e6da49d226).

This is a step-by-step guide to understand first of all the ideas behind EIP-4337 and how it is implemented.
 
But although I understood, why it is there, the reference implementation still was a mystireum to me. To understand it you have to understand the ideas and discussions which have taken place for some years.

The original proposal was written by Vitalik Buterin (@vbuterin), Yoav Weiss (@yoavw), Dror Tirosh (@drortirosh), Shahaf Nacson (@shahafn), Alex Forshtat (@forshtat), Kristof Gazso (@kristofgazso), Tjaden Hess (@tjade273). It is available under "ERC-4337: Account Abstraction Using Alt Mempool [DRAFT]," Ethereum Improvement Proposals, no. 4337, September 2021. [Online serial] [here](https://eips.ethereum.org/EIPS/eip-4337).

The ERC-4337 reference implementation I'm referring to in this tutorial can be found
here on [github](https://github.com/eth-infinitism/account-abstraction/tree/main/contracts)

# Intro - The ideas behind ERC-4337
I found some great explainations on the ideas and concepts which finally led to ERC-4337 on alchemy by David Philipson [here](https://www.alchemy.com/blog/account-abstraction). I tried to summerize it here before we take a deeper look at the reference implementation.

# Part I: Creating a wallet which does not need to handle private keys 
## 1. Smart contract wallet 
Externally owned accounts (EOA) managing private keys and signing transactions are not for everyone. It might be helpful for mass adoption to have "managed accounts". This per defintion can only be implemented as a smart contract which we call "smart (contract) wallet". Each user needs one individual "smart contract wallet" which holds the assets like ETH, ERC20 or NFTs. In the context of ERC-4337 the "smart (contract) wallet" is called "account".

## 2. User operations
Now that we have a "smart (contract) wallet" I would like to do stuff (on chain). For example transfer ETH or some of my assets. Or use another smart contract based service. Means calling one of its functions.

Normally an EOA would send a transaction, but as we do not want an EOA there must be another solution. The authors of EIP-4337 introduced the concept of "user operations" which (similar to a transaction) describes what we want our wallet to do. They define it as:  

> "UserOperation - a structure that describes a transaction to be sent on behalf of a user.  
 To avoid confusion, it is not named “transaction”.  
 Like a transaction, it contains “sender”, “to”, “calldata”, “maxFeePerGas”, “maxPriorityFee”, “signature”, “nonce”.  
 Unlike a transaction, it contains several other fields, described below.  
 Also, the “signature” field usage is not defined by the protocol, but by each account implementation."

The "sender" here is the account contract sending a user operation.

Ok, now we have a wallet which holds our assets and a user operation which describes what we want to do. Now the wallet needs somehow a function to execute the user operation, means something like this:   
```
contract SmartWallet {
  function executeUserOp(UserOperation userOp);
}
```
Next question that comes up is: who will call this function if not an EOA?  

## 3. From bundler to entry point
Generally anyone could call the function `executeUserOp` on our wallet account. So this could be another smart contract or EOA holding some ETH and willing to pay for the gas.  
But nobody would do that just for fun without getting paid. So let's assume that we will pay the caller of `executeUserOp` at the end as part of that function.

The caller executing the `executeUserOp` function on the wallet account is called "bundler" as part of EIP-4337, although this term is a little confusing at this point as the bundler is not  
yet bundling anything.  

So paying the bundler for executing `executeUserOp` sounds great, but how can the bundler be sure to get the money at the end of the transcation when calling a method of an unknown contract?  
One idea is, that he would first simulate the execution of `executeUserOp` to be sure getting paid at the end. But there are different reasons why simulation might not exactly produce the same result as the actual execution of `executeUserOp`. Especially if the wallet account wants to fool the bundler. And limiting these possible reasons would be too much of a restriction on the wallet's possible functionalities. 

To solve this, the authors of ERC-4337 introduced a trustworthy "man in the middle", the so called "entry point". It's an audited contract which implements a function `handleOp(UserOperation userOp);`. The bundler will call this function instead of calling any function of the wallet account directly.

Let's look at the role of the entry point here. The `handleOp` function will do the following:
- Check if the wallet has enough funds to pay to for execution of `executeUserOp`
- Call the wallet account’s `executeUserOp` function
- Send the appropriate amount of ETH to the bundler to pay for the gas

To prevent getting fooled by a malicious wallet account in the same way as the bundler could get fooled, the entry point needs to hold the ETH necessary for the gas-payment. Therefore the entry point contract needs to implement a `deposit` and a `withdraw` function to allow the wallet (or someone on behalf of the wallet) to put ETH into the entry point or take it out later.

Now the bundler and the entry point are safe, but the wallet account might get in trouble as anyone can try to execute he wallet's `executeUserOp`. Of course the execution will fail, as the wallet will validate and identify a malicious user operation but at this point it has already paid for the gas and so someone who wants to fool the wallet can use up all the wallet's gas money.

How to solve this?

## 4. Seperating validation from execution
To manage the problem mentioned above, the wallet account needs to distinguish betwenn validation failures and execution failures. If validation fails this is due to the bundler and the wallet owner is not willing to pay for the gas. If exectution fails, this is due to the code defined by the wallet owner in the user operation. It is like a rejected transaction and the wallet owner has to pay for the gas. This is not possible in the way the wallet account's interface is currently setup. We need to seperate validation from execution. 

Let's do that as follows:
```
contract Wallet {
  function validateUserOp(UserOperation userOp);
  function executeUserOp(UserOperation userOp);
}
```
If `validateUserOp` fails, it simply stops here. No gas money will be payed.
If it succeeds, set aside ETH from the wallet account's deposit to pay for the maximum amount of gas it might possibly use or reject if the wallet account doesn’t have enough. 
Than call `executeUserOp`. No matter if this call succeeds or not, in this case it's the wallet account's responibility. So it has to pay the bundler for the gas from the funds set aside before and return the rest to the wallet account's deposit.

Although the wallet will not execute `executeUserOp` if `validateUserOp` fails, we should prevent any malicious attacks by only allowing a known entry point contract to call these functions.  
So the wallet is safe now and it will only pay for gas if the user oepration was initiated on it's behalf (although it could still fail, like any normal transaction can also fail).

But there is still a small issue for the bundler. In case an unauthorized user operation is submitted to the bundler, who tries to execute this operation, it will fail when calling `validateUserOp`. So that's fine. But in this case the bundler still has to pay for the gas and will not be compensated.

## 5. Simulating `validateUserOp`
We introduced the idea of simulating the execution of a user operation already when introducing the bundler (cf. 3rd idea) but explained that there are different reasons why simulation might not produce the same result as later execution. And limiting these possible reasons would be too much of a restriction on the wallet's possible functionalities. This was when validation and execution were part of one function. Now that we have different functions for each task, it is possible to make restrictions on user operations.

In EIP-4337 the authors define these restrictions as follows:
> "For this purpose, a UserOperation is not allowed to access any information that might change between simulation and execution, such as current block time, number, hash etc. In addition, a UserOperation is only allowed to access data related to this sender address"

## 6. Wallet account paying for gas
The fact that the wallet account deposits ETH in the entry point contract was due to the risk that the execution of the user operation would be called but the wallet account would not pay for gas in the end. Now that we have seperated validation and execution, the wallet account can send the funds to the entry point as part of the validation. It will not be possible to simulate the exact amount of ETH to be paid for the later execution, so the entry point will ask for the maximum amount of gas that might possibly be used. The wallet account can withdraw redundant funds later but this avoids that the wallet account has to deposit large amounts prepaid ETH in the entry point.

The entry point will always try to pay for gas from the wallet's deposit and ask for the remaining funds when calling `validateUserOp`.

## 7. Incentivising the bundler
The bundler will be payed by the wallet account owner via a tip. The amount is defined in the user operation in a field `uint256 maxPriorityFeePerGas`. When calling `handleUserOp` on the entry point contract, the bundler can choose to send a lower `maxPriorityFeePerGas` with the transaction and keep the difference.

## 8. Trusted entry point as singleton 
Technically all bundlers and all wallets can interact with the same entry point. So this can be one audited contract for the whole system. It only has to know to which wallet account a user operation belongs to. Therefore we add a field `sender` to the user operation defining the address of the wallet account.

//-------------------------------------------------- to be validated------------------------------

The entrypoint contract is of type `IEntryPoint` and will be set as a constant in the constructor of `SimpleAccount.sol`.
The actual validation is done in the internal function `_validateSignature(userOp, userOpHash)`. Let's look how this works. The function is implemented in the `SimpleAccount.sol` contract.

```
    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (owner != hash.recover(userOp.signature))
            return SIG_VALIDATION_FAILED;
        return 0;
    }
```
It takes the `userOp` and the `userOpHash` as parameters and checks if the recovered signature of the user operation equals the owner of the wallet or not. In case it does not, the function 
returns the constant `SIG_VALIDATION_FAILED` which equals 1. Else it returns 0.

To retrieve the signing address from the user operation the function uses `.toEthSignedMessageHash()` and `.recover(userOp.signature)`. These are utility functions provided by "@openzeppelin/contracts/utils/cryptography/ECDSA.sol". They can be used to verify that a message was signed by the holder of the private keys of a given address.
You can read more about Elliptic Curve Digital Signature Algorithm (ECDSA) operations [here](https://docs.openzeppelin.com/contracts/4.x/utilities).
A good tutorial on how to apply ECDSA can be found [here](https://dev.to/yusuferdogan/the-elliptic-curve-digital-signature-algorithm-ecdsa-jng)

The `userOpHash` is the public key to validate the user operation and it is generated in the `EntryPoint.sol` contract by the following function: 

```
    function getUserOpHash(UserOperation calldata userOp) public view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }
```

Now we have seen how the `UserOperation` is validated by the `EntryPoint.sol` contract calling `.validateUserOp` of the smart accout but we have not yet clarified what `UserOperation` are and how they look like.
//----------------------------------------------------------------

## 9. Executing the user operation via call data
When seperating validation and exection as part of idea 4, we defined the interface of the wallet account as follows:

```
contract Wallet {
  function validateUserOp(UserOperation userOp);
  function executeUserOp(UserOperation userOp);
}
```

But ERC-4337 does not define an `executeUserOp` function. Instead the user operations contains a field `callData` as bytes. The first four bytes of this data will be interpreted as a function selector and the rest as function arguments. The entry point contract will send a call to the wallet account contract using the `callData` field as a parameter. This all happens as part of the `handleUserOp` function once the user operations have been validated. 

This concept allows wallet accounts to define their own interface, and user operations can be used to call any kind of functions defined in the wallet account contract.

## 10. The bundler starts bundling
Until now the bundler did not bundle anything. It just executes the user operation by calling `handleUserOp` on the entry point contract. As the entry point contract can act independently from any specific wallet account, the bundler could sent more than one user operation to the entry point with one transaction and safe some gas costs.

So the `handleUserOp` function on the entry point contract just has to take an array of user operations as an argument instead of just one.

The new interface of the entry point will now have a function like this:  
`function handleOps(UserOperation[] calldata ops) external;`

And the bundler, as the name says, is now bundling.

A benefit for the bundler is, that it might be possible to get some extra income through MEV (Maximum Extractable Value) by arranging user operations in a most profitable way. But I will not go into the details of MEV here.

## 11. Similarities to block building nodes
In many ways, bundlers act quiete similar to block building nodes. Like EOA holder sent transactions in order to get them included in a block, owners of a smart wallet submit user operations off chain to a bundler node to get them into a bundle.

Bundlers can store validated user ops in a memepool and broadcast them to other bundlers. Over time we might expect that bundlers and block builders will become the same role.

# Part II: let someone else pay for what you want to do -> the paymaster
## 1. The rational behind paymaster
We have now found a concept for a wallet which can execute user operations and does not have to manage private keys. But it still has to pay for gas. As the main objective is to make usage of web3 apps easier, this does not solve a lot. Users will still need to find some ETH to send it to the wallet, which then can pay for exectution of its user operations.

Maybe we can find a way how someone else pays for gas instead of the user.

## 2. The paymaster
The idea of the paymaster allows that someone other then the wallet pays for gas. For example that could be the one providing the dapp to make the use of it easier. Especially for users who do not know how to get some ETH. The paymaster is another smart contract defined in EIP-4337, which is willing to pay for the execution of user operations under certain conditions.

In order to know which paymaster a user operation wants to pay for its gas, we add a field `address paymaster` and a second one `bytes paymasterData`. In this second field we can pass any kind of information for the paymaster to validate if it wants to pay for that specific user operation.

In the EIP-4337 specification these two information are bundled into one field `bytes paymasterAndData` as an optimization. The first 20 bytes define the paymasters address and the rest contains the arbitrary information.

## 3. Entry point checking for paymasters
In order to let the paymaster pay for gas we have to adopt the `handleUserOp` function of the entry point.

So this function will
1. call `validateUserOp` on the wallet contract
2. if there is a paymaster defined in the user operation it will call `validatePaymasterOp`
3. user operations which fail validation are discarded
4. then call `executeUserOp` for each approved user operation and register the amount of gas needed for exection
5. if the user operation has a paymaster defined, this gas will be paid by the paymaster. Otherwise the wallet will pay for it

Just like a smart wallet account, a paymaster will also put some ETH into the entry point contract using its `deposit` function.

## 4. How the bundler avoids to be cheated by a malicious paymaster
It comes back to the same problem for the bundler as described with regard to the wallet account. You remember? In case an unauthorized user operation is submitted to the bundler, which tries to execute this operation, it will fail when calling `validateUserOp`. So that's fine. But in this case the bundler still has to pay for the gas and will not be compensated.

With regard to the `validateUserOp` function we made restrictions that a user operation is only allowed to address its sender's storage.

But that does not match with the idea of a paymaster which per definition is there to pay for user operations from different owners, means different sender addresses. So it shares storage accross all user operations in a bundle using the same paymaster.

A malicious paymaster could DoS the system. More on this kind of attack you can find [here](https://blog.finxter.com/denial-of-service-dos-attack-on-smart-contracts/).

So, how to protect against malicious paymasters?

The first concept is a reputation system where bundlers register how often a paymaster has failed validation and ban paymasters that fail a lot. This kind of system could still be bypassed if a malicious paymaster creates many instances of itself (a Sybil attack).

To restrict this second type of attack surface the authers of EIP-4337 defined that paymasters have to stake ETH. Therefore we need staking functions as part of the entry point contract.

```
contract EntryPoint {
  // ...

  function addStake() payable;
  function unlockStake();
  function withdrawStake(address payable destination);
}
```

In the reference implementation these functions are implemented in the abstract contract `StakeManager.sol` from which the entry point inherits. 

## 5. Using the paymaster to do some action after the operation is done
Up to now the paymaster is called during validation and if this succeeds it can pay for gas. But there is more a paymaster can do.

The idea of the paymaster is to make life easier for non-native blockchain users. So if you want the users of your dapp to be able to pay in US$, you could transfer these payments into a stablecoin like USDC. A paymaster that is allowing users to pay for gas in USDC needs to know how much gas was actually used by the operation so it can calculate how much USDC to charge to the user.

We add a new hook function `postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost)` to the paymaster which the entry point contract can call once the operation has been executed.

So how does that work: the entrypoint calls `validatePaymasterOp` on the paymaster contract. The validation will only succeed if there are enough funds available. But, there could be a case where the validation succeeds but the execution of the user operation will use up all the funds so that the paymaster has nothing to get paid. A simple trick will solve this: if the `postOp` method reverts during execution, the whole transaction will simply revert. In this case we are in the same situation as of before the exection of the user operation. The `postOp` method will then simply be called again and this time it should be able to transfer the funds as we are in the same situation as of before the execution.

The reference implementation does it a little bit different. It holds a deposit, which will only be used to pay for gas fees if the inital transfer of funds fails. It contains a `DepositPaymaster.sol` example, where the `postOp` method looks like this:

```
    /**
     * perform the post-operation to charge the sender for the gas.
     * in normal mode, use transferFrom to withdraw enough tokens from the sender's balance.
     * in case the transferFrom fails, the _postOp reverts and the entryPoint will call it again,
     * this time in *postOpReverted* mode.
     * In this mode, we use the deposit to pay (which we validated to be large enough)
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {

        (address account, IERC20 token, uint256 gasPricePostOp, uint256 maxTokenCost, uint256 maxCost) = abi.decode(context, (address, IERC20, uint256, uint256, uint256));
        //use same conversion rate as used for validation.
        uint256 actualTokenCost = (actualGasCost + COST_OF_POST * gasPricePostOp) * maxTokenCost / maxCost;
        if (mode != PostOpMode.postOpReverted) {
            // attempt to pay with tokens:
            token.safeTransferFrom(account, address(this), actualTokenCost);
        } else {
            //in case above transferFrom failed, pay with deposit:
            balances[token][account] -= actualTokenCost;
        }
        balances[token][owner()] += actualTokenCost;
    }
```


# Part III: Creating a smart wallet contract without owning an EOA before
## 1. Recap: requirements for wallet creation
In part one we have defined how to setup a wallet that can perform tasks onchain without any need of handling private keys of an EOA.
It simply would not make sense if we needed an EOA now to get our smart wallet account deployed onchain.

Let's recap the targets when creating an EOA and apply them on the creation of a smart wallet account:

1. anyone without an EOA should be able to deploy a smart wallet account onchain, either paying with own ETH or letting a paymaster pay for it
2. like with an EOA, where I can create my private key locally and get an account address before having sent any transaction, this should also be possible setting up a smart wallet account

The second requirement can be achieved using the `CREATE2` opcode. It caluculates a new address as a function of:
- 0xFF, a constant that prevents collisions with CREATE
- The sender’s own address
- A salt (an arbitrary value provided by the sender)
- The to-be-deployed contract’s bytecode

This process is called "counterfactual deployments". The function looks like this: `counterfactual_address = hash(0xFF, sender, salt, bytecode)`.

CREATE2 guarantees that if the sender ever deploys bytecode using CREATE2 and the provided salt, it will be stored in `counterfactual_address`.
As bytecode is part of `counterfactual_address`, other participants can rely on the fact that, if a contract is ever deployed to `counterfactual_address`, it will be exactly the one that coresponds to bytecode.

## 2. How to get the wallet onchain
Now we know about the CREAT2 opcode. The first idea which comes to mind is that 
1. the user would simply submit a user operation
2. the user operation should contain some byteCode to setup the smart wallet contract in field called `initCode`
3. the user operation would be passed to the entry point contract via the bundler
4. the entry point could deploy a new smart wallet account in case of a non-empty `initCode` field as part of the `validateUserOp` method

But in this case the user would submit arbitrary bytecode and pass it to the entry point. The entry point will not be able to validate any kind of bytecode in order to avoid that it is malicious and finally does what its intentional scope was.

To solve this problem we introduce factory contacts to call `CREATE2` for calculating the counterfactual address and to deploy a specific kind of wallet.

In the reference implementation there is a sample factory contract called `simpleAccountFacotry.sol`. It contains mainly two methods. The first one calculates the counterfactual address and is implemented as follows:

```
    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address owner,uint256 salt) public view returns (address) {
        return Create2.computeAddress(bytes32(salt), keccak256(abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(
                    address(accountImplementation),
                    abi.encodeCall(SimpleAccount.initialize, (owner))
                )
            )));
    }
```
The second one deploys a smart wallet account which is of type `SimpleAccount`. This refers to the sample implementation of a smart wallet account which you can find in the same folder.

```
    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     */
    function createAccount(address owner,uint256 salt) public returns (SimpleAccount ret) {
        address addr = getAddress(owner, salt);
        uint codeSize = addr.code.length;
        if (codeSize > 0) {
            return SimpleAccount(payable(addr));
        }
        ret = SimpleAccount(payable(new ERC1967Proxy{salt : bytes32(salt)}(
                address(accountImplementation),
                abi.encodeCall(SimpleAccount.initialize, (owner))
            )));
    }
``` 

We add a field `initCode` to the user operation. If initCode is not empty, the first 20 bytes will refer to the factory address. The rest can be information which is passed to the factory contract if needed. There can be different kind of factory contracts for different kind of wallets. If the factory contract has been audited, users now can be sure to get that exact kind of smart wallet account they want. 

One last issue to solve: as with paymasters, a deployment could succeed during simulation but fail during exection. This problem is solved in the exact same way as with paymasters. A factory contract either only accesses storage of the wallet it deploys, or the bundler will restrict storage and methods a factory contract can access. In this case factory contracts will have to stake ETH in the same way as paymasters have to. 

# Part IV: Saving gas with aggregate signatures
The last part is not specific to account abstraction but a more general concept from cryptography to save gas: aggregate signatures.

## 1. What is an Aggregator contract
ERC-4337 supports handling of user operations that use signature aggregators. An Aggregator is a audited helper contract capable of validating an aggregated signature, which means validating mulitple user operations in one batch by verifying only one signature. This reduces gas costs and improves the scalability of processing user operations. Instead of validating each signature for each user operation the Aggrigator validates multiple user operations in just one step.

The Aggregator interface contains 3 functions:

```
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./UserOperation.sol";

/**
 * Aggregated Signatures validator.
 */
interface IAggregator {

    /**
     * validate aggregated signature.
     * revert if the aggregated signature does not match the given list of operations.
     */
    function validateSignatures(UserOperation[] calldata userOps, bytes calldata signature) external view;

    /**
     * validate signature of a single userOp
     * This method is should be called by bundler after EntryPoint.simulateValidation() returns (reverts) with ValidationResultWithAggregation
     * First it validates the signature over the userOp. Then it returns data to be used when creating the handleOps.
     * @param userOp the userOperation received from the user.
     * @return sigForUserOp the value to put into the signature field of the userOp when calling handleOps.
     *    (usually empty, unless account and aggregator support some kind of "multisig"
     */
    function validateUserOpSignature(UserOperation calldata userOp)
    external view returns (bytes memory sigForUserOp);

    /**
     * aggregate multiple signatures into a single value.
     * This method is called off-chain to calculate the signature to pass with handleOps()
     * bundler MAY use optimized custom code perform this aggregation
     * @param userOps array of UserOperations to collect the signatures from.
     * @return aggregatedSignature the aggregated signature
     */
    function aggregateSignatures(UserOperation[] calldata userOps) external view returns (bytes memory aggregatedSignature);
}
```

If a wallet allows for aggregated signatures, it somehow has to define the corresponding Aggregator contract. In the above mentioned example of an BLS based smart wallet account this is done by using a public variable `aggregator` which is initialized in the constructor.

Knowing the Aggregator's address, the bundler can call the `aggregateSignatures` method which will return one signature for a group of user operations with the same Aggregator. Bundlers whitelist the supported aggregators or they might directly hardcode a native version of the signature aggregation algorithm so that a bundler can directly provide the aggregation.

## 2. How does the entry point handle aggregate signatures 
The entrypoint contract uses `handleOps` method for validating and executing a list of user operations. In order to handle a group of aggregated user operations it needs a new method called `handleAggregatedOps` which will call the Aggregator's `validateSignatures` method for each group of aggregated user operations.

Last point: as for paymaster contracts and factory contracts we also want to prevent malicious aggregators which might succeed in validation but fail during execution. Therefore once again we restrict the storage it can access and the opcodes it can use and it also has to stake ETH in the entry point.

The example of an BLS based aggregator contract in the reference implementiation can be found in `contracts/samples/bls/BLSSignatureAggregator.sol`. BLS stands for Boneh–Lynn–Shacham digital signature. More details on BLS signature can be found [here](https://en.wikipedia.org/wiki/BLS_digital_signature).

This conctract contains the following function to stake ETH.

```
    /**
     * allow staking for this aggregator
     * there is no limit on stake or delay, but it is not a problem, since it is a permissionless
     * signature aggregator, which doesn't support unstaking.
     */
    function addStake(IEntryPoint entryPoint, uint32 delay) external payable {
        entryPoint.addStake{value : msg.value}(delay);
    }
```

# Done - but now how to use it?
## 1. How to use it
In a first step we will make use of existing bundler RPCs 

### A) https://kriptonio.com/blog/how-to-create-simple-erc4337-smart-wallet/


### B) Alchemy

### C) https://github.com/stackup-wallet

### D) https://transeptorlabs.io/


### D Sample bundler of reference implementation
https://github.com/eth-infinitism/bundler/blob/main/README.md

# Backup
## Summery User Operations
The `UserOperation` is somehow a pseudo transacation. To avoid Ethereum consensus changes, the creators of ERC-4337 did not attempt to create new transaction types for account-abstracted transactions. Instead, users package up the action they want their account to take in an ABI-encoded struct called a UserOperation: a structure that describes a transaction to be sent on behalf of a user. To avoid confusion, it is not named “transaction”.

Like a transaction, it contains 

| Field | Type | Description |
| ----------- | ----------- | ----------- |
| sender | address | The account making the operation |
| to | address | | 
| nonce | uint256 |	Anti-replay parameter; also used as the salt for first-time account creation |
| callData | bytes | The data to pass to the sender during the main execution call |
| maxFeePerGas | uint256 | Maximum fee per gas (similar to EIP-1559 max_fee_per_gas) |
| maxPriorityFeePerGas | uint256 | Maximum priority fee per gas (similar to EIP-1559 max_priority_fee_per_gas) |
| signature | bytes | Data passed into the account along with the nonce during the verification step |

Unlike a transaction, it contains several other fields

| Field | Type | Description |
| ----------- | ----------- | ----------- | 
| initCode | bytes  | The initCode of the account (needed if and only if the account is not yet on-chain and needs to be created) |
| callGasLimit | uint256 | The amount of gas to allocate the main execution call |
| verificationGasLimit | uint256 | The amount of gas to allocate for the verification step |
| preVerificationGas | uint256 | The amount of gas to pay for to compensate the bundler for pre-verification execution and calldata |
| paymasterAndData | bytes | Address of paymaster sponsoring the transaction, followed by extra data to send to the paymaster (empty for self-sponsored transaction) |

Also, the “nonce” and “signature” fields usage is not defined by the protocol, but by each account implementation 

## Want more on this topic?
Great site on account abtraction -> [github](https://github.com/4337Mafia/awesome-account-abstraction) 
