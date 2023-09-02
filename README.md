# ERC-4337 Accout Abstraction Tutorial
Could not find a good tutorial for those who want to go deeper into the technical details of
ERC-4337 Account Abstraction and how to use it. So I decided to do one myself.

This is a step-by-step guide to understand first of all the ideas behind EIP-4337 and then the technical implementation of ERC-4337.

To get a firt overview what EIP-4337 is about and what it is used for I found this article quiete helpful [medium blog post](https://medium.com/blockchain-at-usc/deep-dive-into-account-abstraction-and-eip-4337-scaling-ethereum-ux-from-0-to-1-c2e6da49d226).
 
But although I understood, why it is there, the reference implementation still was a mystireum to me. To understand it you have to understand the ideas and discussions which have happened over years first.

# Part I: Creating a wallet which does not need to handle private keys 

## 1. The ideas behind ERC-4337
I found a great tutorial on the ideas and concepts which finally led to ERC-4337 on alchemy by David Philipson [here](https://www.alchemy.com/blog/account-abstraction). I tried to summerize it here before we take a deeper look at the reference implementation.

### 1.1 Smart contract wallet 
Externally owned accounts (EOA) managing private keys and signing transactions is not for everyone. It might be helpful for mass adoption to have "managed accounts". This per defintion can only 
be implemented as a smart contract which we call "smart (contract) wallet". Each user needs one individual "smart contract wallet" which holds the assets like ETH, ERC20 or NFTs. In the context of ERC-4337 the "smart (contract) wallet" is called "account".

### 1.2 User operations
Now that I have a "smart (contract) wallet" I would like to do stuff (on chain). For example transfer ETH or some of my assets. Or use another smart contract based service. Means calling one of its functions.

Normally an EOA would send a transaction but as we do not want an EOA there must be another solution. The authors of EIP-4337 introduced the concept of "user operations" which (similar to a transaction) describes what we want our wallet to do. They define it as:  

> "UserOperation - a structure that describes a transaction to be sent on behalf of a user.  
 To avoid confusion, it is not named “transaction”.  
 Like a transaction, it contains “sender”, “to”, “calldata”, “maxFeePerGas”, “maxPriorityFee”, “signature”, “nonce”  
 unlike a transaction, it contains several other fields, described below  
 also, the “signature” field usage is not defined by the protocol, but by each account implementation"

The "sender" here is the account contract sending a user operation.

Ok, now we have a wallet which holds our assets and a user operation which describes what we want to do. Now the wallet needs somehow a function to execute the user operation, means something like this:   
```
contract SmartWallet {
  function executeUserOp(UserOperation userOp);
}
```
Next question that comes up is: who will call this function if not an EOA?  

### 1.3 From bundler to entry point
Generally anyone could call the function `executeUserOp` on our wallet account. So this could be another smart contract or EOA holding some ETH and willing to pay for the gas.  
But nobody would do that just for fun without getting paid. So let's assume that we will pay the caller of `executeUserOp` at the end as part of that function.

The caller executing the `executeUserOp` function on the wallet account is called "bundler" as part of EIP-4337, although this term is a little confusing at this point as the bundler is not  
yet bundling anything.  

So paying the bundler for executing `executeUserOp` sounds great but how can he be sure to get the money at the end of the transcation when calling a method of an unknown contract?  
One idea is, that he would first simulate the execution of `executeUserOp` to be sure getting paid at the end. But there are different reasons why simulation might not exactly produce the same result as the actual execution of `executeUserOp` if the wallet account wants to fool the bundler. And limiting these possible reasons would be too much of a restriction on the wallet's possible functionalities. 

To solve this, the authors of ERC-4337 introduced a trustworthy "man in the middle", the so called "entry point". It's an audited contract which implements a function `handleOp(UserOperation userOp);`.  The bundler will call this function instead of calling any function of the wallet account directly.

Let's look at the role of the entry point here. The `handleOp` function will do the following:
- Check if the wallet has enough funds to pay to for execution of `executeUserOp`
- Call the wallet account’s `executeUserOp` function
- Send the appropriate amount of ETH to the bundler to pay for the gas

To prevent getting fooled by a malicious wallet account in the same way as the bundler could get fooled, the entry point needs to hold the the gas-payment ETH. So the entry point contract needs to implement  a `deposit` and a `withdraw` function to allow the wallet (or someone on behalf of the wallet) to put ETH into the entry point or take it out later.

Now the bundler and entry point are safe, but the wallet account might get in trouble as anyone can try to execute he wallet's `executeUserOp`. Of course the execution will fail, as the wallet will validate and identify a malicious user operation but at this point it has already paid for the gas and so someone who wants to fool the wallet can use up all the wallet's gaz money.

How to solve this?

### 1.4 Seperating validation from execution
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

### 1.5 Simulating `validateUserOp`
We introduced the idea of simulating the execution of a user operation already when introducing the bundler (cf. 3rd idea) but explained that there are different reasons why simulation might not produce the same result as later execution. And limiting these possible reasons would be too much of a restriction on the wallet's possible functionalities. This was when validation and execution were part of one function. Now that we have different functions for each task, it is possible to make restrictions on user operations.

In EIP-4337 the authors define these restrictions as follows:
> "For this purpose, a UserOperation is not allowed to access any information that might change between simulation and execution, such as current block time, number, hash etc. In addition, a UserOperation is only allowed to access data related to this sender address"

### 1.6 Wallet account paying for gas
The fact that the wallet account deposits ETH in the entry point contract was due to the risk that the execution of the user operation would be called but the wallet account would not pay for gas in the end. Now that we have seperated validation and execution, the wallet account can send the funds to the entry point as part of the validation. It will not be possible to simulate the exact amount of Eth to be paid for the later execution, so the entry point will ask for the maximum amount of gas that might possibly be used. The wallet account can withdraw redundant funds later but this avoids that the wallet account has to deposit large amounts prepaid Eth in the entry point.

The entry point will always try to pay for gas from the wallet's deposit and ask for the remaining funds when calling `validateUserOp`.

### 1.7 Incentivising the bundler
The bundler will be payed by the wallet account owner via a tip. The amount is defined in the user operation in a field `uint256 maxPriorityFeePerGas`. When calling `handleUserOp` on the entry point contract, the bundler can choose to send a lower `maxPriorityFeePerGas` with the transaction and keep the difference.

### 1.8 Trusted entry point as singleton 
Technically all bundlers and all wallets can interact with the same entry point. So this can be one audited contract for the whole system. It only has to know to which wallet account a user operation belongs to. Therefore we add a field `sender` to the user operation defining the address of the wallet account.

### 1.9 Executing the user operation via call data
When seperating validation and exection as part of idea 4, we defined the interface of the wallet account as follows:

```
contract Wallet {
  function validateUserOp(UserOperation userOp);
  function executeUserOp(UserOperation userOp);
}
```

But ERC-4337 does not define an `executeUserOp` function. Instead the user operations contains a field `callData` as bytes. The first four bytes of this data will be interpreted as a function selector and the rest as function arguments. The entry point contract will send a call to the wallet account contract using the `callData` field as a parameter. This all happens as part of the `handleUserOp` function once the user operations have been validated. 

This concept allows wallet accounts to define their own interface, and user operations can be used to call any kind of functions defined in the wallet account contract.

### 1.10 The bundler starts bundling
Until now the bundler did not bundle anything. It just executes the user operation by calling `handleUserOp` on the entry point contract. As the entry point contract can act independently from any specific wallet account, the bundler could sent more than one user operation to the entry point with one transaction and safe some gas costs.

So the `handleUserOp` function on the entry point contract just has to take an array of user operations as an argument instead of just one.

The new interface of the entry point will now have a function like this:  
`function handleOps(UserOperation[] calldata ops) external;`

And the bundler as the name says, is now bundling.

A benefit for the bundler is, that it might be possible to get some extra income through MEV (Maximum Extractable Value) by arranging user operations in a most profitable way. But I will not go into the details of MEV here.

### 1.11 Similarities to block building nodes
In many ways, bundlers act quiete similar to block building nodes. Like EOA holder sent transactions in order to get them included in a block, owners of a smart wallet submit user operations off chain to a bundler node to get them into a bundle.

Bundlers can store validated user ops in a memepool and broadcast them to other bundlers. Over time we might expect that bundlers and block builders will bekome the same role.

# Part II: let someone else pay for what you want to do -> the paymaster
## 1. The rational behind paymaster
We have now found a concept for a wallet which can execute user operations and does not have to manage private keys. But it still has to pay for gas. As the main objective is to make usage of web3 apps easier, this does not solve a lot. Users will still need to find some ether to send it to the wallet, which then can pay for exectution of its user operations.

Maybe we can find a way how someone else pays for gas instead of the user.

### 1.1 The paymaster
The idea of the paymaster allows that someone other then the wallet pays for gas. For example that could be the one providing the dapp to make the use of it easier for users who do not know how to get some Eth. The paymaster is another smart contract defined in EIP-4337, which is willing to pay for the execution of user operations under certain conditions.

In order to know which paymaster a user operation wants to pay for its gas, we add a field `address paymaster` and a second one `bytes paymasterData`. In this second field we can pass any kind of information for the paymaster to validate if it wants to pay for that specific user operation.

In the EIP-4337 specification these two information are bundled into one field `bytes paymasterAndData` as an optimization. The first 20 bytes define the paymasters address and the rest contains the arbitrary information.

### 1.3 Entry point checking for paymasters
In order to let the paymaster pay for gas we have to adopt the `handleUserOp` function of the entry point.

So this function will
1. call `validateUserOp` on the wallet contract
2. if there is a paymaster defined in the user operation it will call `validatePaymasterOp`
3. user operations which fail validation are discarded
4. then call `executeUserOp` for each approved user operation and register the amount of gas needed for exection
5. if the user operation has a paymaster defined this gas will be paid by the paymaster. Otherwise the wallet will pay for it

Just like a smart wallet account, a paymaster will also put some Eth into the entry point contract using its `deposit` function.

### 1.4 How the bundler avoids to be cheated by a malicious paymaster
It comes back to the same problem for the bundler as described with regard to the wallet account. You remember? In case an unauthorized user operation is submitted to the bundler, who tries to execute this operation, it will fail when calling `validateUserOp`. So that's fine. But in this case the bundler still has to pay for the gas and will not be compensated.

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

### 1.5 Using the paymaster to do some action after the operation is done
Up to now the paymaster is called during validation and if this succeeds it can pay for gas. But there is more a paymaster can do.

The idea of the paymaster is to make life easier for non-native blockchain users. So if you want the users of your dapp to be able to pay in US$, you could transfer these payments into a stablecoin like USDC. If the paymaster allows to pay for gas in USDC it needs to know how much gas was used in order to calculate how much USDC the user . 
For example, a paymaster that is allowing users to pay for gas in USDC needs to know how much gas was actually used by the operation so it knows how much USDC to charge.

We add a new hook function `postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost)` to the paymaster which the entry point contract can call once the operation has been executed.

So how does that work: the entrypoint calls `validatePaymasterOp` on the paymaster contract. The validation will only succeed if there are enough funds available. But there is a hook. There could be the case where the validation succeeds but the execution of the user operation will use up all the funds so that the paymaster has nothing to get paid. There is a simple trick to solve this. If the `postOp` method reverts during execution, the whole transaction will simply revert. In this case we are in the same situation as of before the exection of the user operation. The `postOp` method will then simply be called again and this time it should be able to transfer the funds as we are in the same situation as of before the execution.

The reference implementation does it a little differently. It holds a deposit, which will only be used to pay for gas fees if the inital transfer of funds fails. 

It has an `DepositPaymaster.sol` example, where postOp method looks like this:

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




# Part V: Implementation
## 2. How it is implemented
Overview on why it is implemented as it is -> https://www.alchemy.com//blog/account-abstraction  

The ERC-4337 reference implementation I'm referring to in this tutorial you will find
 here on [github](https://github.com/eth-infinitism/account-abstraction/tree/main/contracts)

For me as a developer who has not been in the long history of dicussions about account abstraction which has taken place since 2016, the concept
and its implementation solves so many issues that is not obvious at first sight which part of the reference implementations serves which goals.
I will try to make it simple at the beginning going into more details step by step.

### Overview on implementation
So put the Paymaster and Aggregator aside first and start with the most simplest use case:

We have a smart wallet from which we sent a user operation to a bundler node (via RPC). The bundler node then adds the user operation to the alternative
UserOps mempool.

The bundler nodes (nodes supporting the alternitive mempool) send bundles of user operationes to the EntryPoint contract by calling EntryPoint.handleOps().
From there on the bundle transaction is handled the same way as every other on chain transaction, meaning that it is validated and added to a block.

### The Smart Wallet
Ok, let's stop here and go into the details. There is a smart wallet or smart account, which sends a user operation or UserOps. Now let's look at the reference
implementation and see how that works.

The core interface which has to be implemented for a smart account is

 ```
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./UserOperation.sol";

interface IAccount {
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
    external returns (uint256 validationData);
}
```

This interface imports the `UserOperations.sol` and is implemented in the abstract contract `baseAccount.sol`.

The main task of the smart wallet is to  validate user's signature and nonce. So there is only one external function `validateUserOp`.
This was a little strange to me in the beginning. As the whole ERC-4337 is about account abstraction, I expected that there was more logic in
the account contract. But the magic is all happening in the `EntryPoint.sol` to which we are coming later.

What is important to know at this point, is that the `EntryPoint.sol` will validate signature and nonce of a `UserOps` by calling the `validateUserOp` function
and only make the call to the recipient, if this validation returns successfully. So the `validateUserOp` of the smart wallet checks if the caller is the valid entrypoint
and then validates signature and nonce. In case of failure the function must return SIG_VALIDATION_FAILED (1). In case of other failures (e.g. nonce mismatch, or invalid signature format) 
it simply reverts.

So let's see how the function `validateUserOp` is implemented.

As `baseAccount.sol` is an abstract contract, the actual reference implementation takes place in `SimpleAccount.sol` which is upgradable. I'm not going into
the details of upgradeble smart contracts in this tutorial. But if you want to learn more, I recommend this ... tutorial.

Let's have a look at the implementation in `baseAccount.sol`.

```
    /**
     * Validate user's signature and nonce.
     * subclass doesn't need to override this method. Instead, it should override the specific internal validation methods.
     */
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
    external override virtual returns (uint256 validationData) {
        _requireFromEntryPoint();
        validationData = _validateSignature(userOp, userOpHash);
        if (userOp.initCode.length == 0) {
            _validateAndUpdateNonce(userOp);
        }
        _payPrefund(missingAccountFunds);
    }
```

The function takes 3 paramters. `userOp` of type `UserOperation`, `userOpHash` and `missingAccountFunds`. I will not go into the details of each paramerter here but explain
them as we use it.

In a first step the function checks if it has been called from the valid entrypoint contract calling `_requireFromEntryPoint()`. The function does a simple check if `msg.sender` equals the 
initialized entrypoint contract or the owner.

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

### User Operations

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




## 3. How to use it
https://kriptonio.com/blog/how-to-create-simple-erc4337-smart-wallet/




More technical content on account abtraction  ->[github](https://github.com/4337Mafia/awesome-account-abstraction) 
