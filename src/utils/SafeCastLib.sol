// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Safe unsigned integer casting library that reverts on overflow.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SafeCastLib.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/SafeCast.sol)

/*
 * @title SafeCastLib — 带溢出检查的 uint256 向下转型库
 *
 * 功能：将 uint256 安全地转换为更小的 uintN 类型（N = 8, 16, 24, ..., 248），
 *       若值超出目标类型范围则 revert。
 *
 * 特点：
 * 1. 纯 Solidity 实现，无 assembly
 * 2. 覆盖所有 8 位步长的 uint 类型（uint8 ~ uint248，共 31 个函数）
 * 3. 每个函数模式完全一致：require 边界检查 + 直接截断赋值
 * 4. 相比 OpenZeppelin SafeCast：
 *    - 仅处理 uint256 → uintN（无 int 互转、无 uint → int 转换）
 *    - 使用无消息的 require 而非 custom error（revert 时返回空 data，比 OZ 的 4 字节 selector 更省 gas，
 *      但链下无法区分具体是哪个 cast 失败）
 *
 * 设计决策：
 * - 为什么不用一个泛型函数？Solidity 不支持泛型，且返回值类型不同无法统一
 * - 为什么用 `x < 1 << N` 而非 `x <= type(uintN).max`？
 *   两者等价（1 << N == type(uintN).max + 1），编译器会将 `1 << N` 优化为常量，
 *   gas 无差异，写法上更简洁
 * - 为什么没有 safeCastTo256？uint256 → uint256 无需转换
 */
library SafeCastLib {
    // ========== 以下 31 个函数模式完全相同 ==========
    // 模式：
    //   1. require(x < 1 << N) — 若 x ≥ 2^N（即超出 uintN 范围），revert（无错误信息）
    //   2. y = uintN(x)        — 截断高位，保留低 N 位赋值给返回值
    //
    // 覆盖范围：uint248, uint240, uint232, ..., uint16, uint8（步长 8）
    //
    // 常用位宽场景：
    //   uint160 — 与 address 位宽相同
    //   uint128 — Uniswap V3 流动性（UniswapV3Pool.liquidity）
    //             https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Pool.sol
    //   uint112 — Uniswap V2 储备量（UniswapV2Pair.reserve0/reserve1，与 uint32 打包进同一 slot）
    //             https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol
    //   uint96  — Compound COMP 代币余额与投票权（Comp.balances/Checkpoint.votes）
    //             https://github.com/compound-finance/compound-protocol/blob/master/contracts/Governance/Comp.sol
    //   uint64  — 时间戳（block.timestamp 虽为 uint256，但实际值远小于 2^64）
    //   uint48  — ERC-4337 UserOperation 有效期（validUntil/validAfter）
    //             https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/account/utils/draft-ERC4337Utils.sol
    //   uint32  — block.number、Uniswap V2 blockTimestampLast
    //   uint24  — Uniswap V3 手续费（UniswapV3Factory.fee，单位：百万分之一）
    //             https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Factory.sol
    //   uint8   — decimals、角色编号等

    // uint256 → uint248（最大值：2^248 - 1）
    function safeCastTo248(uint256 x) internal pure returns (uint248 y) {
        require(x < 1 << 248);

        y = uint248(x);
    }

    // uint256 → uint240（最大值：2^240 - 1）
    function safeCastTo240(uint256 x) internal pure returns (uint240 y) {
        require(x < 1 << 240);

        y = uint240(x);
    }

    // uint256 → uint232（最大值：2^232 - 1）
    function safeCastTo232(uint256 x) internal pure returns (uint232 y) {
        require(x < 1 << 232);

        y = uint232(x);
    }

    // uint256 → uint224（最大值：2^224 - 1）
    function safeCastTo224(uint256 x) internal pure returns (uint224 y) {
        require(x < 1 << 224);

        y = uint224(x);
    }

    // uint256 → uint216（最大值：2^216 - 1）
    function safeCastTo216(uint256 x) internal pure returns (uint216 y) {
        require(x < 1 << 216);

        y = uint216(x);
    }

    // uint256 → uint208（最大值：2^208 - 1）
    function safeCastTo208(uint256 x) internal pure returns (uint208 y) {
        require(x < 1 << 208);

        y = uint208(x);
    }

    // uint256 → uint200（最大值：2^200 - 1）
    function safeCastTo200(uint256 x) internal pure returns (uint200 y) {
        require(x < 1 << 200);

        y = uint200(x);
    }

    // uint256 → uint192（最大值：2^192 - 1）
    function safeCastTo192(uint256 x) internal pure returns (uint192 y) {
        require(x < 1 << 192);

        y = uint192(x);
    }

    // uint256 → uint184（最大值：2^184 - 1）
    function safeCastTo184(uint256 x) internal pure returns (uint184 y) {
        require(x < 1 << 184);

        y = uint184(x);
    }

    // uint256 → uint176（最大值：2^176 - 1）
    function safeCastTo176(uint256 x) internal pure returns (uint176 y) {
        require(x < 1 << 176);

        y = uint176(x);
    }

    // uint256 → uint168（最大值：2^168 - 1）
    function safeCastTo168(uint256 x) internal pure returns (uint168 y) {
        require(x < 1 << 168);

        y = uint168(x);
    }

    // uint256 → uint160（最大值：2^160 - 1）
    function safeCastTo160(uint256 x) internal pure returns (uint160 y) {
        require(x < 1 << 160);

        y = uint160(x);
    }

    // uint256 → uint152（最大值：2^152 - 1）
    function safeCastTo152(uint256 x) internal pure returns (uint152 y) {
        require(x < 1 << 152);

        y = uint152(x);
    }

    // uint256 → uint144（最大值：2^144 - 1）
    function safeCastTo144(uint256 x) internal pure returns (uint144 y) {
        require(x < 1 << 144);

        y = uint144(x);
    }

    // uint256 → uint136（最大值：2^136 - 1）
    function safeCastTo136(uint256 x) internal pure returns (uint136 y) {
        require(x < 1 << 136);

        y = uint136(x);
    }

    // uint256 → uint128（最大值：2^128 - 1）
    function safeCastTo128(uint256 x) internal pure returns (uint128 y) {
        require(x < 1 << 128);

        y = uint128(x);
    }

    // uint256 → uint120（最大值：2^120 - 1）
    function safeCastTo120(uint256 x) internal pure returns (uint120 y) {
        require(x < 1 << 120);

        y = uint120(x);
    }

    // uint256 → uint112（最大值：2^112 - 1）
    function safeCastTo112(uint256 x) internal pure returns (uint112 y) {
        require(x < 1 << 112);

        y = uint112(x);
    }

    // uint256 → uint104（最大值：2^104 - 1）
    function safeCastTo104(uint256 x) internal pure returns (uint104 y) {
        require(x < 1 << 104);

        y = uint104(x);
    }

    // uint256 → uint96（最大值：2^96 - 1）
    function safeCastTo96(uint256 x) internal pure returns (uint96 y) {
        require(x < 1 << 96);

        y = uint96(x);
    }

    // uint256 → uint88（最大值：2^88 - 1）
    function safeCastTo88(uint256 x) internal pure returns (uint88 y) {
        require(x < 1 << 88);

        y = uint88(x);
    }

    // uint256 → uint80（最大值：2^80 - 1）
    function safeCastTo80(uint256 x) internal pure returns (uint80 y) {
        require(x < 1 << 80);

        y = uint80(x);
    }

    // uint256 → uint72（最大值：2^72 - 1）
    function safeCastTo72(uint256 x) internal pure returns (uint72 y) {
        require(x < 1 << 72);

        y = uint72(x);
    }

    // uint256 → uint64（最大值：2^64 - 1）
    function safeCastTo64(uint256 x) internal pure returns (uint64 y) {
        require(x < 1 << 64);

        y = uint64(x);
    }

    // uint256 → uint56（最大值：2^56 - 1）
    function safeCastTo56(uint256 x) internal pure returns (uint56 y) {
        require(x < 1 << 56);

        y = uint56(x);
    }

    // uint256 → uint48（最大值：2^48 - 1）
    function safeCastTo48(uint256 x) internal pure returns (uint48 y) {
        require(x < 1 << 48);

        y = uint48(x);
    }

    // uint256 → uint40（最大值：2^40 - 1）
    function safeCastTo40(uint256 x) internal pure returns (uint40 y) {
        require(x < 1 << 40);

        y = uint40(x);
    }

    // uint256 → uint32（最大值：2^32 - 1）
    function safeCastTo32(uint256 x) internal pure returns (uint32 y) {
        require(x < 1 << 32);

        y = uint32(x);
    }

    // uint256 → uint24（最大值：2^24 - 1）
    function safeCastTo24(uint256 x) internal pure returns (uint24 y) {
        require(x < 1 << 24);

        y = uint24(x);
    }

    // uint256 → uint16（最大值：2^16 - 1 = 65535）
    function safeCastTo16(uint256 x) internal pure returns (uint16 y) {
        require(x < 1 << 16);

        y = uint16(x);
    }

    // uint256 → uint8（最大值：2^8 - 1 = 255）
    function safeCastTo8(uint256 x) internal pure returns (uint8 y) {
        require(x < 1 << 8);

        y = uint8(x);
    }
}
