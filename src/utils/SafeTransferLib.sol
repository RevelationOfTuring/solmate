// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

import {ERC20} from "../tokens/ERC20.sol";

/// @notice Safe ETH and ERC20 transfer library that gracefully handles missing return values.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol)
/// @dev Use with caution! Some functions in this library knowingly create dirty bits at the destination of the free memory pointer.
/*
 * @notice 安全的ETH 和 ERC20 转账库，能优雅地处理缺少返回值的代币
 * @dev 1. 本库不校验 token/to地址的有效性，调用方需自行保证地址正确。
 *      2. 本库全部函数会在 free memory pointer 处写入 calldata 但不更新 0x40（省 gas），不影响正确性
 *
 * 解决的核心问题：
 *   ERC20 标准规定 transfer/transferFrom/approve 应返回 bool，但早期代币（如 USDT、BNB）
 *   不返回任何值。直接用Solidity 高级调用会因ABI 解码失败而 revert。
 *   本库通过手动构造 calldata +灵活解析返回值，兼容三种代币行为：
 *     1. 标准代币：返回 true（32 字节）
 *     2. 非标代币：不返回值（0 字节），如USDT
 *     3. 异常情况：返回false 或 call失败 → revert
 *
 * 设计亮点：
 *   - 全assembly 实现，避免 Solidity 编译器插入的 ABI 编解码开销
 *   - 返回值写入 scratch space（0x00-0x1f），而非 free memory pointer 之后，节省内存分配
 *   - 地址参数用 and(addr, 0xff...ff) 掩码清理高位脏数据，防止 ABI 编码污染
 */
library SafeTransferLib {
    /*//////////////////////////////////////////////////////////////
                             ETH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 安全转账 ETH，失败时 revert
     * @param to 接收地址
     * @param amount 转账金额（wei）
     *
     * 注意：
     * - 不做 address(0) 检查，调用方需自行保证
     * - 如果 to 是合约且 receive/fallback 消耗大量 gas，call 可能因 gas 不足失败
     */
    function safeTransferETH(address to, uint256 amount) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // call(gas, to, value, inputOffset, inputSize, outputOffset, outputSize)
            // 转账 ETH：不传 calldata（inputSize=0），不将返回值拷贝到内存（outputSize=0）
            // 如果存在返回值，即在to的fallback/receive函数中使用Yul return，那么其会在 returndata 缓冲区中，可通过 returndatasize/returndatacopy 读取
            // gas() 传递所有剩余 gas（因为接收方可能是合约，需要执行 receive/fallback）
            success := call(gas(), to, amount, 0, 0, 0, 0)
        }

        // 如果call失败，直接revert
        require(success, "ETH_TRANSFER_FAILED");
    }

    /*//////////////////////////////////////////////////////////////
                            ERC20 OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /*
     * @dev 安全调用 ERC20.transferFrom(from, to, amount)
     * @param token ERC20 代币合约
     * @param from   转出地址
     * @param to     转入地址
     * @param amount 转账金额
     *
     * 兼容不返回值的非标代币（如 USDT）
     */
    function safeTransferFrom(ERC20 token, address from, address to, uint256 amount) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // 获取 free memory pointer，用作calldata 的写入起点
            let freeMemoryPointer := mload(0x40)

            // ========== 手动构造 ABI 编码的 calldata ==========

            // 写入 4 字节函数选择器：transferFrom(address,address,uint256)
            // 0x23b872dd = bytes4(keccak256("transferFrom(address,address,uint256)"))
            // mstore 写入 32 字节，选择器占前 4 字节，后 28 字节填充 0
            mstore(freeMemoryPointer, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
            // 写入第1 个参数 from（偏移 4 字节）
            // and(from, 0xff...ff) 掩码清理高 96 位，确保地址只占低 20 字节
            // 为什么要清理？Solidity 不保证 address 类型高位为零，脏数据会污染 ABI 编码
            // 本质原因：EVM 的 word 是 256 位，address 只占低 160 位。Solidity 编译器在大多数场景会自动清理高位，
            // 但 assembly 块和底层操作绕过了编译器的类型系统，如：
            //      uint256 raw = 0xFF00000000000000000000001234567890abcdef12345678;
            //      address a = address(uint160(raw));  // ✅ 安全，截断高位
            //      address b;
            //      assembly { b := raw }              // ❌ 高位脏数据保留
            // SafeTransferLib 作为底层库，不能假设调用方一定用了Solidity 高级语法传参——做防御性掩码是安全库的标准做法
            mstore(add(freeMemoryPointer, 4), and(from, 0xffffffffffffffffffffffffffffffffffffffff))
            // 写入第 2 个参数 to（偏移 36 = 4 + 32 字节）
            mstore(add(freeMemoryPointer, 36), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            // 写入第 3 个参数 amount（偏移 68 = 4 + 32 + 32 字节）
            // uint256 占满 32 字节，无需掩码
            mstore(add(freeMemoryPointer, 68), amount)

            // ========== 执行外部调用 ==========

            // call(gas, addr, value, inputOffset, inputSize, outputOffset, outputSize)
            // inputSize = 100= 4（选择器）+ 32×3（三个参数）
            // outputOffset = 0, outputSize = 32：返回值写入 scratch space（0x00-0x1f）
            success := call(gas(), token, 0, freeMemoryPointer, 100, 0, 32)

            // ========== 返回值校验（核心逻辑）==========

            // 此时 success = call是否成功（未revert）
            // mload(0) = scratch space 中的返回值（call 已将最多 32 字节拷贝到此处）
            // returndatasize() = 对方实际返回的字节数
            //
            // 目标：在 call 成功的前提下，进一步校验返回值是否合法
            // 合法的两种情况：
            //   情况1：标准代币：返回了 >= 32 字节，且值为 1（true）
            //   情况2：非标代币（如 USDT）：返回了 0 字节，但目标地址确实是合约
            //
            // 代码拆解：
            //   isStandard = and(eq(mload(0), 1), gt(returndatasize(), 31))
            //     → 返回值 == 1 且 returndatasize >= 32（属于情况1）
            //
            //   if and(iszero(isStandard), success)
            //     → call 成功但不满足情况1，需要进一步判断是否属于情况2
            //     → 如果 call 失败（success=0），and结果为 0，跳过 if 体，
            //       success 保持 false，最终被 require捕获
            //
            //   if 体内：
            //     success := iszero(or(iszero(extcodesize(token)), returndatasize()))
            //       → extcodesize(token) > 0（是合约）且 returndatasize == 0（无返回值）
            //       → 两个条件同时满足 → success = true（情况2）
            //       → 否则 success = false（返回了非 1 的值，或者调了个 EOA）
            //
            // 换成solidity：
            //  if (success && !(mload(0) == 1 && returndatasize() > 31)) {
            //      // 进一步判断：是合约 且 无返回值 → 非标代币成功
            //      success = (extcodesize(token) > 0) && (returndatasize() == 0);
            //  }
            // 注: Yul 版本把Solidity 的两层 && 短路都换成了平铺的 and，省了两个 JUMPI
            if and(iszero(and(eq(mload(0), 1), gt(returndatasize(), 31))), success) {
                success := iszero(or(iszero(extcodesize(token)), returndatasize()))
            }
            // 最终 success为true 代表：call成功+返回true 或 call成功+无返回值+是合约
        }

        // 如果success为false，直接revert
        require(success, "TRANSFER_FROM_FAILED");
    }

    /*
     * @dev 安全调用 ERC20.transfer(to, amount)
     * @param token  ERC20 代币合约
     * @param to     转入地址
     * @param amount 转账金额
     *
     * 兼容不返回值的非标代币（如 USDT）
     */
    function safeTransfer(ERC20 token, address to, uint256 amount) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // 获取 free memory pointer，用作calldata 的写入起点
            let freeMemoryPointer := mload(0x40)

            // 写入函数选择器：transfer(address,uint256)
            // 0xa9059cbb = bytes4(keccak256("transfer(address,uint256)"))
            mstore(freeMemoryPointer, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            // 写入参数 to（掩码清理高位）
            mstore(add(freeMemoryPointer, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            // 写入参数 amount
            mstore(add(freeMemoryPointer, 36), amount)
            // calldata 长度 = 4 + 32×2 = 68
            // 返回值写入 scratch space
            success := call(gas(), token, 0, freeMemoryPointer, 68, 0, 32)

            // 返回值校验逻辑同safeTransferFrom
            if and(iszero(and(eq(mload(0), 1), gt(returndatasize(), 31))), success) {
                success := iszero(or(iszero(extcodesize(token)), returndatasize()))
            }
        }

        // 如果success为false，直接revert
        require(success, "TRANSFER_FAILED");
    }

    /*
     * @dev 安全调用 ERC20.approve(spender, amount)
     * @param token  ERC20 代币合约
     * @param to     被授权地址（spender）
     * @param amount 授权金额
     *
     * 兼容不返回值的非标代币（如 USDT）
     * 注意：USDT 的 approve 要求先将 allowance 设为 0 再设新值，本函数不处理此逻辑
     */
    function safeApprove(ERC20 token, address to, uint256 amount) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // 获取 free memory pointer，用作calldata 的写入起点
            let freeMemoryPointer := mload(0x40)

            // 写入函数选择器：approve(address,uint256)
            // 0x095ea7b3 = bytes4(keccak256("approve(address,uint256)"))
            mstore(freeMemoryPointer, 0x095ea7b300000000000000000000000000000000000000000000000000000000)
            // 写入参数 to（spender，掩码清理高位）
            mstore(add(freeMemoryPointer, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            // 写入参数 amount
            mstore(add(freeMemoryPointer, 36), amount)

            // calldata 长度 = 4 + 32×2 = 68
            // 返回值写入 scratch space
            success := call(gas(), token, 0, freeMemoryPointer, 68, 0, 32)

            // 返回值校验逻辑同 safeTransferFrom
            if and(iszero(and(eq(mload(0), 1), gt(returndatasize(), 31))), success) {
                success := iszero(or(iszero(extcodesize(token)), returndatasize()))
            }
        }

        // 如果success为false，直接revert
        require(success, "APPROVE_FAILED");
    }
}
