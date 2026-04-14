// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Gas optimized reentrancy protection for smart contracts.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/ReentrancyGuard.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/security/ReentrancyGuard.sol)
/*
 * @title ReentrancyGuard —防重入保护的抽象合约
 * @notice 提供 nonReentrant modifier，防止函数在执行期间被重入调用
 *
 * 设计亮点：
 * 1. 使用 1/2 而非 0/1 作为锁状态
 * 2. 标记为 abstract：不能单独部署，必须被继承
 * 3. modifier 标记为 virtual：子合约可以 override 扩展逻辑
 */
abstract contract ReentrancyGuard {
    /*
     * @dev 重入锁状态变量
     * - 1 = 未锁定（可进入）
     * - 2 = 已锁定（禁止重入）
     *
     * 为什么初始化为 1 而不是 0？
     * - EVM 中，storage slot 从 0 改为非 0 消耗 20000 gas（cold write）
     * - 从非 0 改为非 0 只消耗 5000 gas（EIP-2200 SSTORE 规则）
     * - 初始化为 1，后续 1→2→1 切换都是非0→非0，节省 15000 gas
     */
    uint256 private locked = 1;

    /*
     * @dev 防重入修饰符
     * @notice 被此修饰符保护的函数在执行期间不能被重入调用
     *
     * 重入攻击防护原理：
     * - 若函数体中调用了外部合约，外部合约试图回调本合约的 nonReentrant 函数
     * - 此时 locked == 2，require 失败，交易 revert
     *
     * virtual 关键字：允许子合约 override 此modifier 以扩展行为（如添加事件）
     */
    modifier nonReentrant() virtual {
        // 检查是否未锁定，若已锁定则 revert "REENTRANCY"
        require(locked == 1, "REENTRANCY");
        // 上锁，标记为"执行中"
        locked = 2;

        // 执行被修饰的函数体
        _;

        // 解锁，恢复为"可进入"状态
        locked = 1;
    }
}
