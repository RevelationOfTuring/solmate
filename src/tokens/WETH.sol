// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

import {ERC20} from "./ERC20.sol";

import {SafeTransferLib} from "../utils/SafeTransferLib.sol";

/// @notice Minimalist and modern Wrapped Ether implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/WETH.sol)
/// @author Inspired by WETH9 (https://github.com/dapphub/ds-weth/blob/master/src/weth9.sol)
/*
 * 功能总结：
 * 极简的 Wrapped Ether（WETH）实现，将原生 ETH 包装为 ERC20 代币
 *
 * 核心功能：
 * - deposit：存入 ETH，铸造等量 WETH（ERC20 代币）
 * - withdraw：销毁 WETH，取回等量 ETH
 * - receive：直接向合约转 ETH 时自动调用 deposit
 *
 * 设计亮点：
 * 1. 1:1 锚定：合约持有的 ETH 余额始终等于 WETH 的 totalSupply
 * 2. 非 abstract：可直接部署，无需子合约继承
 * 3. 所有函数标记 virtual：允许子合约覆写（如添加费用、白名单等）
 * 4. receive() 兜底：直接转 ETH 也能自动包装，不会丢失
 *
 * 为什么需要 WETH？
 * - ETH 是原生代币，不遵循 ERC20 接口，无法直接用于 DeFi 协议（如 Uniswap、Aave）
 * - WETH 将 ETH 包装为标准 ERC20，使其可以像普通代币一样 approve/transferFrom
 * - 几乎所有 DeFi 协议都通过 WETH 统一处理 ETH 交互
 *
 * 什么时候用 solmate 的 WETH？
 * - 每条链都有自己的"官方"WETH（以太坊主网是 WETH9：0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2），
 *   主网上不会再部署新的 WETH，但以下场景会用到 solmate 的实现：
 * 1. 测试环境：Foundry/Hardhat 本地链没有预部署 WETH，测试 DeFi 协议时需要自己部署一个
 * 2. 新链/L2/Appchain 首发部署：新链上线时还没有官方 WETH，且 solmate 版本比 WETH9（Solidity 0.4）
 *    更现代化（0.8+、内置 permit、SafeTransferLib）
 * 3. 代码集成：DeFi 协议已依赖 solmate，需要 WETH 类型做接口定义时直接 import，无需额外引入 WETH9
 */
contract WETH is ERC20("Wrapped Ether", "WETH", 18) {
    using SafeTransferLib for address;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    // 存款事件：from 存入 amount 数量的 ETH，获得等量 WETH
    event Deposit(address indexed from, uint256 amount);

    // 取款事件：to 销毁 amount 数量的 WETH，取回等量 ETH
    event Withdrawal(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            DEPOSIT / WITHDRAW
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice 存款：将随交易发送的 ETH 包装为 WETH
     * @dev msg.value 即为存入金额，铸造等量 WETH 给 msg.sender
     *      调用继承自 ERC20 的 _mint，更新 totalSupply 和 balanceOf
     */
    function deposit() public payable virtual {
        // 铸造等量 WETH（ERC20._mint 会更新 totalSupply + balanceOf）
        _mint(msg.sender, msg.value);

        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice 取款：销毁 WETH，取回等量 ETH
     * @dev 遵循 CEI 模式：先销毁代币（Effect），再发送 ETH（Interaction）
     *      使用 SafeTransferLib.safeTransferETH 而非 transfer，
     *      因为 transfer 有 2300 gas 限制，若接收方是合约可能 revert
     * @param amount 取款数量（WETH 销毁量 = ETH 返还量）
     */
    function withdraw(uint256 amount) public virtual {
        // 先销毁 WETH（余额不足会 underflow revert）
        _burn(msg.sender, amount);

        emit Withdrawal(msg.sender, amount);

        // 最后发送 ETH（CEI 模式：Interaction 放最后）
        // safeTransferETH 使用 call 而非 transfer，无 2300 gas 限制
        msg.sender.safeTransferETH(amount);
    }

    /*//////////////////////////////////////////////////////////////
                             RECEIVE FALLBACK
    //////////////////////////////////////////////////////////////*/

    // 接收 ETH 的兜底函数：当用户直接向 WETH 合约转 ETH（不附带 calldata）时自动触发
    // 效果等同于调用 deposit()——ETH 不会丢失，自动包装为 WETH
    receive() external payable virtual {
        deposit();
    }
}
