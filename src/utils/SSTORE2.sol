// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Read and write to persistent storage at a fraction of the cost.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SSTORE2.sol)
/// @author Modified from 0xSequence (https://github.com/0xSequence/sstore2/blob/master/contracts/SSTORE2.sol)
/*
 * 功能总结：
 * SSTORE2 —— 利用合约字节码（contract code）作为廉价的持久化存储方案。
 *
 * 核心问题：
 * - SSTORE（写storage）：每 32 字节首次写入 22,100 gas（EIP-2200）
 * - 部署合约（写 code）：每字节仅 200 gas
 * - 当数据量较大时（> 约 4KB），写入合约字节码比写storage 便宜得多
 * - 读取也更便宜：EXTCODECOPY 100 gas 基础+ 3 gas/字 vs SLOAD 每32 字节 2100 gas
 *
 * 实现原理：
 *   写入（write）：
 *     1. 将数据作为合约的runtime bytecode 部署到链上
 *     2. 在数据前面加一个 STOP（0x00）操作码，防止合约被意外调用执行
 *     3. 返回新部署合约的地址（pointer），作为"存储指针"
 *   读取（read）：
 *     1. 用 EXTCODECOPY 从pointer 地址读取字节码
 *     2. 跳过第1 个字节（STOP 操作码），返回原始数据
 *
 * 权衡：
 *   - 数据一旦写入不可修改（合约字节码是immutable的）
 *   - 每次写入都是一次新的合约部署（新地址）
 *   - 数据上限约 24,575 字节（= 24,576 合约大小上限 - 1 字节 STOP）
 *
 * 典型使用场景：
 *   - 链上存储大段不可变数据（如元数据、图片、配置）
 *   - NFT 的 tokenURI 数据存储
 *   - 大数组/大字符串的链上存储
 */
library SSTORE2 {
    /*
     * @dev 数据在合约字节码中的起始偏移量
     * 值为 1，因为字节码的第 0 个字节是 STOP（0x00），不属于用户数据
     * 读取时需要跳过这1 个字节
     */
    uint256 internal constant DATA_OFFSET = 1;

    /*//////////////////////////////////////////////////////////////
                               WRITE LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 将数据写入链上（部署为一个新合约的字节码）
     * @param data 要存储的任意字节数据
     * @return pointer 新部署合约的地址，作为后续读取的"存储指针"
     *
     * 部署的合约结构：
     *   字节码 = [0x00（STOP）]++ [data]
     *   - STOP：确保合约不会被意外调用执行
     *   - data：紧跟其后，占据剩余全部字节码空间
     */
    function write(bytes memory data) internal returns (address pointer) {
        // 在数据前加一个 STOP（0x00）操作码，作为部署后的合约字节码
        // 即 [STOP] ++ [data]，上限为代码大小限制 - 1 字节
        // STOP的作用：如果有人尝试 call 这个合约，EVM 遇到 STOP 会立即停止，不会执行到后面的数据
        bytes memory runtimeCode = abi.encodePacked(hex"00", data);

        // 构造creationCode = initcode（11 字节）++ runtimeCode
        // initcode 的作用：将 runtimeCode 从 code 区拷贝到内存，返回给CREATE
        bytes memory creationCode = abi.encodePacked(
            //---------------------------------------------------------------------------------------------------------------
            // Opcode  | Opcode + Arguments  | Description  | Stack View
            //---------------------------------------------------------------------------------------------------------------
            // 0x60    |  0x600B             | PUSH1 11     | codeOffset(11)
            //   → 11 = initcode 自身的长度（0x0B），runtimeCode 从偏移 11 开始
            // 0x59    |  0x59               | MSIZE        | 0 codeOffset(11)
            //   → MSIZE：返回当前内存最高使用地址，此时内存未使用，返回 0
            //   → 与 CREATE3 使用 RETURNDATASIZE 压0 类似的gas 优化技巧
            // 0x81    |  0x81               | DUP2         | codeOffset(11) 0 codeOffset(11)
            //   → DUP2：复制栈上从顶部往下数第 2 个元素，压到栈顶。全部助记符为DUP1～DUP16
            // 0x38    |  0x38               | CODESIZE     | codeSize codeOffset(11) 0 codeOffset(11)
            //   → CODESIZE = initcode 长度 + runtimeCode 长度（即整个 creationCode 的总长度），相当于Yul内置函数——codesize()
            // 0x03    |  0x03               | SUB          | (codeSize - codeOffset(11)) 0 codeOffset(11)
            //   → codeSize - 11 = runtimeCode 的长度，（= 1 字节 STOP + data.length）
            // 0x80    |  0x80               | DUP1         | (codeSize - codeOffset(11)) (codeSize - codeOffset(11)) 0 codeOffset(11)
            // 0x92    |  0x92               | SWAP3        | codeOffset(11) (codeSize - codeOffset(11)) 0 (codeSize - codeOffset(11))
            //   → 重新排列栈顶（SWAP3：把栈顶和从顶部往下数第 4 个元素互换位置），为CODECOPY 准备参数：destOffset=0, offset=codeOffset, size
            // 0x59    |  0x59               | MSIZE        | 0 codeOffset(11) (codeSize - codeOffset(11)) 0 (codeSize - codeOffset(11))
            // 0x39    |  0x39               | CODECOPY     | 0 (codeSize - codeOffset(11))
            //   → CODECOPY(destOffset=0, offset=11, size=runtimeCodeLength)
            //   → 将 runtimeCode 从 code 区拷贝到内存 0x00 开始的位置
            // 0xf3    |  0xf3               | RETURN       |
            //   → RETURN(offset=0, size=runtimeCodeLength)
            //   → 从内存中返回 runtimeCode 给外层正在执行的 CREATE。CREATE 收到后将其写入链上，作为新合约的 deployed code
            //     注：CREATE 的本质——执行输入的字节码（initcode），然后把内存中RETURN出来的东西部署到链上
            //---------------------------------------------------------------------------------------------------------------
            hex"60_0B_59_81_38_03_80_92_59_39_F3", // initcode
            runtimeCode // runtimecode
        );

        /// @solidity memory-safe-assembly
        assembly {
            // 用CREATE部署合约，返回新合约地址。如果部署失败返回 address(0)
            // create(value, offset, size)：
            //   - 0：不转ETH
            //   - add(creationCode, 32)：跳过 bytes 的 32 字节长度前缀
            //   - mload(creationCode)：读取 creationCode 的长度
            pointer := create(0, add(creationCode, 32), mload(creationCode))
        }

        // 部署失败则revert（如creationCode 为空，或超出合约大小限制）
        require(pointer != address(0), "DEPLOYMENT_FAILED");
    }

    /*//////////////////////////////////////////////////////////////
                               READ LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 读取 pointer 合约中存储的全部数据
     * @param pointer write() 返回的合约地址
     * @return 存储的原始数据（已跳过开头的 STOP 字节）
     */
    function read(address pointer) internal view returns (bytes memory) {
        // pointer.code.length = STOP(1字节) + data 长度
        // 跳过 DATA_OFFSET(1) 字节，读取剩余全部
        return readBytecode(pointer, DATA_OFFSET, pointer.code.length - DATA_OFFSET);
    }

    /*
     * @dev 读取 pointer 合约中从 start 开始到末尾的数据（切片读取）
     * @param pointer write() 返回的合约地址
     * @param start 数据的起始偏移量（相对于用户数据，不含 STOP 字节）
     * @return 从 start 到末尾的数据
     */
    function read(address pointer, uint256 start) internal view returns (bytes memory) {
        // 加上 DATA_OFFSET 转换为字节码中的实际偏移量
        start += DATA_OFFSET;

        return readBytecode(pointer, start, pointer.code.length - start);
    }

    /*
     * @dev 读取 pointer 合约中 [start, end) 范围的数据（切片读取）
     * @param pointer write() 返回的合约地址
     * @param start   数据的起始偏移量（相对于用户数据，不含 STOP 字节）
     * @param end     数据的结束偏移量（不包含，即左闭右开区间）
     * @return [start, end) 范围内的数据
     */
    function read(address pointer, uint256 start, uint256 end) internal view returns (bytes memory) {
        // 加上 DATA_OFFSET 转换为字节码中的实际偏移量
        start += DATA_OFFSET;
        end += DATA_OFFSET;

        // 越界检查：end 不能超过合约字节码的总长度
        require(pointer.code.length >= end, "OUT_OF_BOUNDS");

        return readBytecode(pointer, start, end - start);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL HELPER LOGIC
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 底层读取函数：用 EXTCODECOPY 从合约字节码中读取指定范围的数据
     * @param pointer 目标合约地址
     * @param start   字节码中的起始偏移量（调用方已加上 DATA_OFFSET）
     * @param size    要读取的字节数
     * @return data   读取到的字节数据
     */
    function readBytecode(address pointer, uint256 start, uint256 size) private view returns (bytes memory data) {
        /// @solidity memory-safe-assembly
        assembly {
            // 获取空闲内存指针
            data := mload(0x40)

            // 更新空闲内存指针，防止后续内存操作覆盖我们的数据
            // 新指针 = data + 32（长度前缀）+ size，并向上对齐到 32 字节边界
            // and(x, not(31)) 等价于 x - (x % 32)，即x对32向下取整，更省gas
            // 加31再对32向下取整 = 向上对齐到 32 的倍数
            mstore(0x40, add(data, and(add(add(size, 32), 31), not(31))))

            // 在 data 的前 32 字节存储数据长度
            mstore(data, size)

            // 用 EXTCODECOPY 将pointer合约的字节码拷贝到内存中
            // extcodecopy(addr, destOffset, offset, size)：
            //   - pointer：目标合约地址
            //   - add(data, 32)：跳过 32 字节长度前缀，拷贝到数据区
            //   - start：字节码中的起始偏移量
            //   - size：要拷贝的字节数
            extcodecopy(pointer, add(data, 32), start, size)
        }
    }
}
