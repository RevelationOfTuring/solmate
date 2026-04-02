// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Library for converting between addresses and bytes32 values.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/Bytes32AddressLib.sol)
/*
 * 功能总结：
 * bytes32 与 address 之间的互转工具库。
 *
 * 核心特点：
 * - 仅包含两个 pure 函数，零gas 存储开销
 * - fromLast20Bytes：从 bytes32 的低 20 字节提取 address（右对齐）
 * - fillLast12Bytes：将 address 填入 bytes32 的高 20 字节（左对齐），低 12 字节补零
 * - 两个函数的对齐方式不同，不是互逆操作
 *
 * 内存布局对比（32 字节 = 256 bit）：
 *
 * fromLast20Bytes（右对齐，取低 20 字节）：
 *   bytes32: [0x 00000000 00000000 00000000 aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa]
 *                高 12 字节（丢弃）                   低 20 字节 → address
 *
 * fillLast12Bytes（左对齐，填高 20 字节）：
 *   bytes32: [0x aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa 00000000 00000000 00000000]
 *                高 20 字节 ← address                   低 12 字节（补零）
 *
 * 典型使用场景：
 * - CREATE2 预计算地址时，keccak256 返回 bytes32，需要取低 20 字节作为 address
 * - 将 address 编码为 bytes32 用于 abi.encodePacked 拼接
 */
library Bytes32AddressLib {
    /*
     * @dev 从 bytes32 的低 20 字节中提取 address（右对齐提取）
     * @param bytesValue 原始 bytes32 值
     * @return address   提取出的地址
     *
     * 类型转换链：
     *   bytes32 → uint256 → uint160 → address
     *
     * 拆解：
     *   1. uint256(bytesValue)— bytes32 转为 256 位无符号整数（值不变）
     *   2. uint160(...)          — 截断高 96 位，保留低 160 位（=20 字节）
     *   3. address(...)— uint160 转为 address 类型
     *
     * 示例：
     *   bytesValue = 0x000000000000000000000000d8dA6BF26964aF9D7eEd9e03E53415D37aA96045
     *   → uint256 = 0x...d8dA6BF26964aF9D7eEd9e03E53415D37aA96045
     *   → uint160 截断高位 = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
     *   → address = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
     *
     * 典型场景：CREATE2 预计算地址
     *address predicted = fromLast20Bytes(keccak256(abi.encodePacked(
     *       bytes1(0xff), deployer, salt, codeHash
     *   )));
     */
    function fromLast20Bytes(bytes32 bytesValue) internal pure returns (address) {
        return address(uint160(uint256(bytesValue)));
    }

    /*
     * @dev 将 address 填入 bytes32 的高 20 字节，低 12 字节补零（左对齐填充）
     * @param addressValue 原始地址
     * @return bytes32     左对齐后的 bytes32 值
     *
     * 类型转换链：
     *   address → bytes20 → bytes32
     *
     * 拆解：
     *   1. bytes20(addressValue) — address 转为 20 字节定长字节数组
     *   2. bytes32(...)          — bytes20 扩展为 bytes32，bytesN 扩展时右侧补零
     *
     * 关键知识点：
     *   - bytesN 是左对齐的（数据在高位，补零在低位）
     *   - uintN 是右对齐的（补零在高位，数据在低位）
     *   这就是为什么 fromLast20Bytes 和 fillLast12Bytes 不是互逆操作
     *
     * 示例：
     *   addressValue = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
     *   → bytes20 = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
     *   → bytes32 = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045000000000000000000000000
     *                                                         ^^^^^^^^^^^^^^^^^^^^^^^^
     *                                                               低 12 字节补零
     *
     * 使用场景：当你需要把 address 按左对齐格式塞进32 字节的内存 slot 时，用它把低 12 字节补零。
     *   一般用汇编模拟 abi.encodePacked 时，就需要左对齐：
     *   mstore 只能写 32 字节，左对齐让address 占据高位，低 12 字节补零可以被后续 mstore 安全覆盖，从而模拟 abi.encodePacked 的紧凑排列。
     */
    function fillLast12Bytes(address addressValue) internal pure returns (bytes32) {
        return bytes32(bytes20(addressValue));
    }
}
