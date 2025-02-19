// SPDX-License-Identifier: MIT
// by 0xAA
pragma solidity ^0.8.4;

contract SelectorClash {
    bool public solved; // Was the attack successful?

    function putCurEpochConPubKeyBytes(bytes memory _bytes) public {
        require(msg.sender == address(this), "Not Owner");
        solved = true;
    }

    function executeCrossChainTx(bytes memory _method, bytes memory _bytes) public returns(bool success){
        (success, ) = address(this).call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bytes,bytes,uint64)"))), abi.encode(_bytes)));
    }

    function secretSlector() external pure returns(bytes4){
        return bytes4(keccak256("putCurEpochConPubKeyBytes(bytes)"));
    }

    function hackSlector() external pure returns(bytes4){
        return bytes4(keccak256("f1121318093(bytes,bytes,uint64)"));
    }
}
