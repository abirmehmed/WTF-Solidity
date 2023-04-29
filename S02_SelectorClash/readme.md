---
title: S02. selector collision
tags:
  - solidity
  - security
  - selector
  - abi encode
---

# WTF Solidity Contract Security: S02. Selector Collision

 I recently relearned solidity, consolidated some details, and wrote a “WTF Solidity Simplified Introduction” for beginners (programming experts can find other tutorials), updated 1-3 lectures per week.

 Twitter：[@0xAA_Science](https://twitter.com/0xAA_Science)

community ：[Discord](https://discord.gg/5akcruXrsk)｜[WeChat group](https://docs.google.com/forms/d/e/1FAIpQLSe4KGT8Sh6sJ7hedQRuIYirOoZK_85miz3dw7vA1-YjodgJ-A/viewform?usp=sf_link)｜[official website wtf.academy](https://wtf.academy)

all code and tutorials are open source github: [github.com/AmazingAng/WTFSolidity](https://github.com/AmazingAng/WTFSolidity)

-----

 In this lecture, we will introduce selector collision attack, which is one of the reasons why cross-chain bridge Poly Network was hacked. In August 2021, Poly Network’s cross-chain bridge contracts on ETH, BSC, and Polygon were stolen, resulting in a loss of up to $611 million ([summary] (https://rekt.news/zh/polynetwork-rekt/)）。This is the biggest blockchain hacking incident in 2021, and also the second on the historical stolen amount list, second only to Ronin Bridge hacking incident. 

## Selector collision

In Ethereum smart contracts, the function selector is the first `4` bytes (`8 `hexadecimal digits) of the hash value of the function signature `"<function name>(<function input types>)"`. When a user calls a contract’s function, the first `4` bytes of `calldata` are the selector of the target function, determining which function is called. If you are not familiar with it, you can read [WTF Solidity Minimalist Tutorial Lecture 29: Function Selector].

(https://github.com/AmazingAng/WTFSolidity/blob/main/29_Selector/readme.md)。

Since the function selector is only `4` bytes, it is very short and easy to collide: that is, we can easily find two different functions with the same function selector. For example, `transferFrom(address,address,uint256)` and `gasprice_bit_ether(int128)` have the same selector: `0x23b872dd`. Of course, you can also write a script to brute force it.

![](./img/S02-1.png)

Everyone can use these two websites to check different functions corresponding to the same selector:

1. https://www.4byte.directory/
2. https://sig.eth.samczsun.com/

You can also use the `Power Clash` tool below for brute force cracking:

1. PowerClash: https://github.com/AmazingAng/power-clash

In contrast, the public key of a wallet has `256` bytes, and the probability of being collided is almost `0`, which is very safe.

## `0xAA` Solve the mystery of the Sphinx.”


The people of Ethereum offended the gods, and the gods were furious. In order to punish the people of Ethereum, Hera, the queen of the gods, sent down a female demon with a human face and a lion’s body named Sphinx on the cliff of Ethereum. She posed a riddle to every Ethereum user who passed by the cliff: ‘What walks on four legs in the morning, two legs at noon, and three legs in the evening? Among all creatures, this is the only one that walks with different numbers of legs. When it has the most legs, it is when its speed and strength are at their weakest.’ For this mysterious and puzzling riddle, those who guessed it could survive, and those who couldn’t guess it were eaten. All passers-by were eaten by Sphinx, and Ethereum users were plunged into fear. Sphinx used the selector `0x10cd2dc7` to verify whether the answer was correct.

One morning, Oedipus passed by this place and met the female demon and guessed the mysterious and profound riddle. He said: ‘This is `function man()`! In the morning of life, he is a child, crawling on two legs and two hands; at noon of life, he becomes a strong man and walks on two legs; in the evening of life, he is old and weak and must walk with the help of a cane, so he is called three-legged.’ After the riddle was solved, Oedipus survived

That afternoon, `0xAA` passed by this place and met the female demon and guessed the mysterious and profound riddle. He said: ‘This is `function peopleLduohW(uint256)`! In the morning of life, he is a child, crawling on two legs and two hands; at noon of life, he becomes a strong man and walks on two legs; in the evening of life, he is old and weak and must walk with the help of a cane, so he is called three-legged.’ After the riddle was solved again, Sphinx was furious and slipped from the towering cliff and fell to her death.

![](./img/S02-2.png)


## Example of a vulnerable contract.

### Vulnerable contract.

Let’s take a look at an example of a vulnerable contract. The `SelectorClash` contract has `1` state variable `solved`, initialized to `false`, and the attacker needs to change it to `true`. The contract mainly has `2` functions, and the function names are inherited from the Poly Network vulnerability contract.

1. `putCurEpochConPubKeyBytes()`: After the attacker calls this function, he can change `solved` to `true` and complete the attack. However, this function checks `msg.sender == address(this)`, so the caller must be the contract itself, and we need to look at other functions.
2. `executeCrossChainTx()`: It can be used to call functions within the contract, but the type of function parameters is not quite the same as the target function: the target function’s parameters are `(bytes)`, while the function called here has parameters `(bytes,bytes,uint64)`.

```solidity
contract SelectorClash {
    bool public solved; // Was the attack successful?

    // The attacker needs to call this function, but the caller msg.sender must be this contract.
    function putCurEpochConPubKeyBytes(bytes memory _bytes) public {
        require(msg.sender == address(this), "Not Owner");
        solved = true;
    }

    // There is a vulnerability, and the attacker can collide the function selector by changing the _method variable, call the target function and complete the attack.
    function executeCrossChainTx(bytes memory _method, bytes memory _bytes, bytes memory _bytes1, uint64 _num) public returns(bool success){
        (success, ) = address(this).call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bytes,bytes,uint64)"))), abi.encode(_bytes, _bytes1, _num)));
    }
}
```

### Attack method

Our goal is to use the `executeCrossChainTx()` function to call the `putCurEpochConPubKeyBytes()` in the contract. The selector of the target function is: `0x41973cd9`. It is observed that the `executeCrossChainTx()` uses the _method parameter and '`(bytes,bytes,uint64)`' as the function signature to calculate the selector. Therefore, we only need to select the appropriate `_method` so that the calculated selector here is equal to `0x41973cd9`, and call the target function through selector collision.


In the Poly Network hacker incident, the hacker collided `_method` to `f1121318093`, that is, the first 4 bits of the hash of `f1121318093(bytes,bytes,uint64)` are also `0x41973cd9`, which can successfully call the function. Next, what we have to do is to convert `f1121318093` into a `bytes` type: `0x6631313231333138303933`, and then input it as a parameter into `executeCrossChainTx()`. The other 3 parameters of the `executeCrossChainTx()` function are not important, fill in `0x`, `0x`, `0`.

## `Remix`Demonstration

1. Deploy the `SelectorClash` contract.
2. Call `executeCrossChainTx()` with the parameters `0x6631313231333138303933`, `0x`, `0x`, and `0` to initiate the attack.
3. Check the value of the `solved` variable. If it has been changed to `true`, the attack was successful.

## summary

In this lecture, we introduced the selector clash attack, which is one of the reasons why the cross-chain bridge Poly Network was hacked for 610 million US dollars. This attack tells us:

1. Function selectors are easily clashed, and even if the parameter types are changed, functions with the same selector can still be constructed.

2. Manage the permissions of contract functions well to ensure that functions with special permissions in the contract cannot be called by users.
