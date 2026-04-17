// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @notice Efficient library for creating string representations of integers.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/LibString.sol)
/// @author Modified from Solady (https://github.com/Vectorized/solady/blob/main/src/utils/LibString.sol)
/*
 * @title LibString — 高效的整数转字符串库
 * @notice 提供 int256 / uint256 → 十进制字符串的纯 assembly 实现
 *
 * 设计亮点：
 * 1. 纯 assembly 实现，零 Solidity 高级语法开销
 * 2. 预分配 160 字节（5 words），从右向左写入数字字符
 * 3. do-while 循环模式（for {} 1 {}）天然处理 value=0
 * 4. 负数利用左侧空余空间插入 '-'，无需重新分配内存
 *
 * ASCII 参考：'0'=48, '9'=57, '-'=45
 */
library LibString {
    /*
     * @dev 将 int256 转换为十进制字符串
     * @param value 要转换的有符号整数
     * @return str 十进制字符串（负数带 '-' 前缀）
     *
     * 处理策略：
     * - 正数/零：直接委托给 uint256 版本
     * - 负数：先取绝对值转字符串，再在前面插入 '-'
     *
     * 为什么 sub(str, 1) 是安全的？
     * - toString(uint256) 分配了 160 字节但最多只用 78 字节
     * - 字符串从右向左写入，str 前面一定有空余空间
     */
    function toString(int256 value) internal pure returns (string memory str) {
        // 正数/零：直接走 uint256 版本
        if (value >= 0) return toString(uint256(value));

        // 为什么用 unchecked？
        // 取反操作 -value 在 value = type(int256).min（= -2^255）时会溢出，
        // 即 -(-2^255) = 2^255，超出 int256 最大值 2^255 - 1。 Solidity 0.8+ 默认溢出检查会 revert
        // unchecked 关闭溢出检查，2^255 的补码表示经 uint256() 转换后得到合法的 2^255
        unchecked {
            // 负数：先取绝对值转字符串（-123 → "123"）
            str = toString(uint256(-value));

            /// @solidity memory-safe-assembly
            assembly {
                /*
                 * 在字符串前面插入 '-' 字符
                 *
                 * Solidity string 内存布局：str → [length][char0][char1]...[charN]
                 *
                 * 操作步骤：
                 * 1. 读取当前长度（如 "123" → 3）
                 * 2. 在 length slot 位置写入 '-'（ASCII 45）
                 * 3. 指针前移 1 字节，为新 length slot 腾位置
                 * 4. 写入新长度（3+1=4）
                 *
                 * 最终布局：[4]['-']['1']['2']['3']
                 */
                // 读取当前字符串长度
                let length := mload(str)
                // 45 = ASCII '-'，覆盖原 length slot
                mstore(str, 45)
                // 指针前移 1 字节
                str := sub(str, 1)
                // 写入新长度 = 原长度 + 1
                mstore(str, add(length, 1))
            }
        }
    }

    /*
     * @dev 将 uint256 转换为十进制字符串（核心实现）
     * @param value 要转换的无符号整数
     * @return str 十进制字符串
     *
     * 算法：从右到左逐位提取十进制数字，写入预分配的内存区域
     * 1. 分配 160 字节内存，str 指向末尾
     * 2. 循环：mod 10 取最低位 → 转 ASCII → mstore8 写入 → div 10 去掉最低位
     * 3. 计算实际长度，在数字字符前面写入 length slot
     *
     * 为什么分配 160 字节（5 words）？
     *
     * - uint256 最大值 2^256 - 1 = 115792089237316195423570985008687907853269984665640564039457584007913129639935，
     * 有 78 位十进制数字，数字本身只需要 78 字节。
     * 但代码中有两处 mstore 操作，各自需要预留 32 字节空间：
     *
     * 1) 右侧：mstore(str, 0) —— 清零最后一个 word
     *    - Solidity string 在 ABI 编码时，最后一个 word 不足 32 字节的部分必须补零
     *    - 例如 "123" 只有 3 字节，但内存中占 1 word = [0x313233 000...000]
     *    - 如果不清零，尾部可能有脏数据
     *    - mstore 一次写 32 字节，所以 str 必须从 sub(newFreeMemoryPointer, 32) 开始
     *    - 这 32 字节专门用于清零，不存储数字字符
     *
     * 2) 左侧：mstore(str, length) —— 写入字符串长度
     *    - Solidity string 内存布局要求前 32 字节为 length slot
     *    - mstore 一次写 32 字节，所以数字字符左边必须预留完整的 32 字节
     *
     * 总计：32（length slot）+ 78（数字字符）+ 32（尾部清零）= 142 字节
     * 向上对齐到 32 字节边界 = 160 字节（5 × 32）
     * 额外的 18 字节空间还可供 toString(int256) 向左插入 '-' 使用
     *
     * 内存布局（以 78 位数字为例）：
     *   [0 .............. 17][18 ........... 49][50 ......... 127][128 ......... 159]
     *    ↑ 空余（18字节）      ↑ length slot      ↑ 数字字符         ↑ 尾部清零 word
     *                         mstore(str,length)  mstore8 逐字节写入  mstore(str,0)
     *
     * value=0 的处理：
     * - do-while 循环（for {} 1 {}）至少执行一次，写入 '0'，返回 "0"
     */
    function toString(uint256 value) internal pure returns (string memory str) {
        /// @solidity memory-safe-assembly
        assembly {
            // 在当前空闲内存指针基础上分配 160 字节
            let newFreeMemoryPointer := add(mload(0x40), 160)
            // 更新空闲内存指针
            mstore(0x40, newFreeMemoryPointer)

            // str 指向分配区域末尾减 1 word
            str := sub(newFreeMemoryPointer, 32)
            // 清零最后一个 word（防止脏数据）
            mstore(str, 0)
            // 记录末尾位置，用于计算长度
            let end := str

            /*
             * 从右向左逐位提取数字
             *
             * do-while 循环（for { let temp := value } 1 {} 模式）：
             * - 条件为 1（永真），在循环体内用 if + break 退出
             * - 至少执行一次，天然处理 value=0（写入 '0'）
             * - 比 for {} lt(...) {} 省一次初始比较
             */
            // prettier-ignore
            for { let temp := value } 1 {} {
                // 指针左移 1 字节
                str := sub(str, 1)
                // mod(temp, 10) 取最低位 + 48 转 ASCII → 将这1字节写入str对应的内存
                mstore8(str, add(48, mod(temp, 10)))
                // 去掉最低位
                temp := div(temp, 10)

                // 如果商为 0，表示所有位都处理完了，退出循环
                // 如果商不为 0，表示还有位待处理，继续循环
                // prettier-ignore
                if iszero(temp) { break }
            }

            // 计算字符串实际长度 = end（最初尾部位置）- str（当前最高位位置）
            let length := sub(end, str)
            // 指针左移 32 字节，为 length slot 腾空间
            str := sub(str, 32)
            // 在 str 位置写入字符串长度
            mstore(str, length)

            // 最终布局：[length]['d1']['d2']...['dN'][0...padding]
        }
    }
}
