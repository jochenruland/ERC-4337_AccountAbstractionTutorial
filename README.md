# ERC-4337 Accout Abstraction Tutorial
Could not find a good tutorial for those who want to go deeper into the technical details of
ERC-4337 Account Abstraction and how to use it. So I decided to do one myself.

This is a step-by-step tutorial to the technical implementation of ERC-4337 Account Abstraction

## 1. What is about
Overview on what ERC-4337 ist about -> [medium blog post](https://medium.com/blockchain-at-usc/deep-dive-into-account-abstraction-and-eip-4337-scaling-ethereum-ux-from-0-to-1-c2e6da49d226)
More technical content on account abtraction  ->[github](https://github.com/4337Mafia/awesome-account-abstraction)


## 2. How it is implemented
Please find the ERC-4337 reference implementation I'm referring to in this tutorial here on [github](https://github.com/eth-infinitism/account-abstraction/tree/main/contracts)

For me as a developer who has not been in the long history of dicussions about account abstraction which has taken place since 2016, the concept
and its implementation solves so many issues that is not obvious at first sight which part of the reference implementations serves which goals.
I will try to make it simple at the beginning going into more details step by step.

### Overview
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

To retrieve the signing address from the user operation the function uses `.toEthSignedMessageHash()` and `.recover(userOp.signature)`. These are utility functions provided by "@openzeppelin/contracts/utils/cryptography/ECDSA.sol". These functions can be used to verify that a message was signed by the holder of the private keys of a given address.
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
| sender | address | The account making the operation |
| to | address | | 
| nonce | uint256 |	Anti-replay parameter; also used as the salt for first-time account creation |
| callData | bytes | The data to pass to the sender during the main execution call |
| maxFeePerGas | uint256 | Maximum fee per gas (similar to EIP-1559 max_fee_per_gas) |
| maxPriorityFeePerGas | uint256 | Maximum priority fee per gas (similar to EIP-1559 max_priority_fee_per_gas) |
| signature | bytes | Data passed into the account along with the nonce during the verification step |

Unlike a transaction, it contains several other fields

| Field | Type | Description |
| initCode | bytes  | The initCode of the account (needed if and only if the account is not yet on-chain and needs to be created) |
| callGasLimit | uint256 | The amount of gas to allocate the main execution call |
| verificationGasLimit | uint256 | The amount of gas to allocate for the verification step |
| preVerificationGas | uint256 | The amount of gas to pay for to compensate the bundler for pre-verification execution and calldata |
| paymasterAndData | bytes | Address of paymaster sponsoring the transaction, followed by extra data to send to the paymaster (empty for self-sponsored transaction) |

Also, the “nonce” and “signature” fields usage is not defined by the protocol, but by each account implementation 




3. How to use it
https://kriptonio.com/blog/how-to-create-simple-erc4337-smart-wallet/





