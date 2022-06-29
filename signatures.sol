// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.7;


library Signatures{

    function getMessage(address recipient, uint256 amount) 
        public 
        pure 
        returns(bytes32 message) 
    {
        message = keccak256(abi.encodePacked(recipient, amount));
    }

    function getSigner(uint256 amount, bytes memory signature)
        public
        view
        returns (address)
    {
        bytes32 message = keccak256(abi.encodePacked(tx.origin, amount));

        // to check that the signature is from the payment sender
        return recoverSigner(prefixed(message), signature);
    }

    ////////
    /// signature methods from solidity docs.
    function splitSignature(bytes memory sig)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(sig.length == 65);

        assembly {
            // first 32 bytes, after the length prefix.
            r := mload(add(sig, 32))
            // second 32 bytes.
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes).
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function recoverSigner(bytes32 message, bytes memory sig)
        internal
        pure
        returns (address)
    {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);

        return ecrecover(message, v, r, s);
    }

    /// builds a prefixed hash to mimic the behavior of eth_sign.
    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

}

